import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";

import type {
  DoctorProviderCheck,
  DoctorProviderInspection,
} from "../application/Doctor.js";
import {
  execFileOutput,
  execFileOutputFailure,
} from "../process/ExecFileOutput.js";
import {
  admitFirmwareVersion,
  firmwareEngineLabel,
  firmwareReleaseLine,
  type FirmwareEngineName,
} from "./FirmwareVersion.js";

const PROBE_TIMEOUT_MS = 10_000;
const PROBE_OUTPUT_BYTES = 64 * 1024;
const PROCESS_LIST_ARGUMENTS = [
  "-axo",
  "pid=,ppid=,pgid=,uid=,stat=,command=",
] as const;

type ProbeOutput = Awaited<ReturnType<typeof execFileOutput>>;
type ProbeRunner = (
  command: string,
  arguments_: readonly string[],
  options: {
    readonly env: Readonly<NodeJS.ProcessEnv>;
    readonly timeout: number;
    readonly maxBuffer: number;
  },
) => Promise<ProbeOutput>;

/** Injectable read-only host boundary for deterministic firmware doctor tests. */
export interface FirmwareDoctorHost {
  readonly platform: NodeJS.Platform;
  readonly processId: number;
  resolveExecutable(path: string): Promise<string>;
  run: ProbeRunner;
}

/** Inspect both caller-supplied firmware engines without launching an analysis. */
export const inspectFirmwareProviders = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  host: FirmwareDoctorHost = systemFirmwareDoctorHost(),
): Promise<readonly DoctorProviderInspection[]> =>
  Promise.all(
    (["binwalk", "unblob"] as const).map((engine) =>
      inspectFirmwareProvider(engine, environment, host),
    ),
  );

const inspectFirmwareProvider = async (
  engine: FirmwareEngineName,
  environment: Readonly<NodeJS.ProcessEnv>,
  host: FirmwareDoctorHost,
): Promise<DoctorProviderInspection> => {
  const variable =
    engine === "binwalk" ? "REA_BINWALK_COMMAND" : "REA_UNBLOB_COMMAND";
  const configuredPath = environment[variable];
  const configured = configuredPath !== undefined && configuredPath.length > 0;
  const checks: DoctorProviderCheck[] = [platformCheck(host.platform)];

  const command = await executableCheck({
    name: "configuration",
    label: `${firmwareEngineLabel(engine)} executable`,
    variable,
    configuredPath,
    host,
    absentClassification: "missing_analysis_engine",
  });
  checks.push(command.check);

  const limiterPath =
    environment.REA_FIRMWARE_PRLIMIT_COMMAND ?? "/usr/bin/prlimit";
  const limiter = await executableCheck({
    name: "prlimit",
    label: "util-linux prlimit",
    variable: "REA_FIRMWARE_PRLIMIT_COMMAND",
    configuredPath: limiterPath,
    host,
    absentClassification: "missing_dependency",
  });
  checks.push(limiter.check);

  const processOwnership = await psCheck(environment, host);
  checks.push(processOwnership);

  let providerVersion: string | null = null;
  if (host.platform === "linux" && command.path !== undefined) {
    const version = await versionCheck(engine, command.path, environment, host);
    checks.push(version.check);
    providerVersion = version.version;
  }

  if (
    engine === "unblob" &&
    host.platform === "linux" &&
    command.path !== undefined
  )
    checks.push(
      await externalDependenciesCheck(command.path, environment, host),
    );

  return {
    id: engine,
    configured,
    available: configured && checks.every(({ ok }) => ok),
    providerVersion,
    // Firmware paths are operation configuration, not client-registration
    // settings owned by setup. Keep doctor read-only and avoid persisting them.
    registrationEnvironment: {},
    checks,
  };
};

const platformCheck = (platform: NodeJS.Platform): DoctorProviderCheck => ({
  name: "platform",
  ok: platform === "linux",
  code: platform === "linux" ? null : "unsupported_host",
  detail:
    platform === "linux"
      ? "Linux firmware provider host is supported."
      : `Firmware providers require Linux; current host is ${platform}.`,
  remediation:
    platform === "linux"
      ? null
      : "Run the firmware workflow with Linux REA and caller-supplied firmware tools.",
  classification: "unsupported_host",
});

const executableCheck = async (input: {
  readonly name: string;
  readonly label: string;
  readonly variable: string;
  readonly configuredPath: string | undefined;
  readonly host: FirmwareDoctorHost;
  readonly absentClassification:
    | "missing_dependency"
    | "missing_analysis_engine";
}): Promise<{ readonly path: string | undefined; readonly check: DoctorProviderCheck }> => {
  const { configuredPath } = input;
  if (configuredPath === undefined || configuredPath.length === 0)
    return {
      path: undefined,
      check: {
        name: input.name,
        ok: false,
        code: "not_configured",
        detail: `${input.variable} is not configured.`,
        remediation: `Set ${input.variable} to an absolute executable path for the caller-supplied ${input.label}.`,
        classification: input.absentClassification,
      },
    };
  if (!isAbsolute(configuredPath))
    return {
      path: undefined,
      check: {
        name: input.name,
        ok: false,
        code: "path_not_absolute",
        detail: `${input.variable} must be absolute: ${configuredPath}`,
        remediation: `Set ${input.variable} to an absolute executable path for the caller-supplied ${input.label}.`,
        classification: "config_drift",
      },
    };
  try {
    const path = await input.host.resolveExecutable(configuredPath);
    return {
      path,
      check: {
        name: input.name,
        ok: true,
        code: null,
        detail: `${input.label} validated at ${path}.`,
        remediation: null,
        classification: "config_drift",
      },
    };
  } catch (cause: unknown) {
    return {
      path: undefined,
      check: {
        name: input.name,
        ok: false,
        code: "executable_unavailable",
        detail: `${input.variable} is unavailable: ${errorMessage(cause)}`,
        remediation: `Point ${input.variable} at a readable executable regular file.`,
        classification: input.absentClassification,
      },
    };
  }
};

const versionCheck = async (
  engine: FirmwareEngineName,
  command: string,
  environment: Readonly<NodeJS.ProcessEnv>,
  host: FirmwareDoctorHost,
): Promise<{ readonly version: string | null; readonly check: DoctorProviderCheck }> => {
  try {
    const output = await runProbe(host, command, ["--version"], environment);
    if (output.stdoutBytes > 1024)
      return {
        version: null,
        check: failedCheck(
          "version",
          "version_banner_too_large",
          `${firmwareEngineLabel(engine)} version banner is ${String(output.stdoutBytes)} bytes; expected a short version line.`,
          `Install ${firmwareReleaseLine(engine)} and rerun rea doctor.`,
          "config_drift",
        ),
      };
    const banner = output.stdout.trim();
    const admission = admitFirmwareVersion(engine, banner);
    if (admission.status === "unsupported" || admission.status === "unresolved")
      return {
        version: null,
        check: failedCheck(
          "version",
          "unsupported_version",
          admission.message,
          `Install ${firmwareReleaseLine(engine)} and rerun rea doctor.`,
          "config_drift",
        ),
      };
    return {
      version: admission.version,
      check: {
        name: "version",
        ok: true,
        code: null,
        detail:
          admission.status === "verified"
            ? `${firmwareEngineLabel(engine)} ${admission.version} matches the verified release.`
            : admission.limitation,
        remediation: null,
        classification: "config_drift",
      },
    };
  } catch (cause: unknown) {
    return {
      version: null,
      check: probeFailureCheck(
        "version",
        "version_probe_failed",
        cause,
        `Run the configured ${firmwareEngineLabel(engine)} executable with --version and correct the reported failure.`,
        "runtime_failure",
      ),
    };
  }
};

const psCheck = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  host: FirmwareDoctorHost,
): Promise<DoctorProviderCheck> => {
  if (host.platform !== "linux")
    return failedCheck(
      "process-ownership",
      "unsupported_host",
      "The procps ownership prerequisite is only used by the Linux firmware integration.",
      "Run the firmware workflow on Linux.",
      "unsupported_host",
    );
  try {
    const output = await runProbe(host, "ps", PROCESS_LIST_ARGUMENTS, environment);
    const currentPid = String(host.processId);
    const reported = output.stdout
      .split("\n")
      .some((line) => line.trimStart().startsWith(`${currentPid} `));
    if (!reported)
      return failedCheck(
        "process-ownership",
        "incompatible_ps",
        "ps did not report REA's current process using the required procps-compatible process-table format.",
        "Install procps/procps-ng or another compatible ps on REA's PATH, then rerun rea doctor.",
        "missing_dependency",
      );
    return {
      name: "process-ownership",
      ok: true,
      code: null,
      detail: "procps-compatible ps is available for Linux process ownership checks.",
      remediation: null,
      classification: "missing_dependency",
    };
  } catch (cause: unknown) {
    return probeFailureCheck(
      "process-ownership",
      "ps_unavailable",
      cause,
      "Install procps/procps-ng or another compatible ps on REA's PATH, then rerun rea doctor.",
      "missing_dependency",
    );
  }
};

const externalDependenciesCheck = async (
  command: string,
  environment: Readonly<NodeJS.ProcessEnv>,
  host: FirmwareDoctorHost,
): Promise<DoctorProviderCheck> => {
  try {
    const output = await runProbe(
      host,
      command,
      ["--show-external-dependencies"],
      environment,
    );
    return {
      name: "external-dependencies",
      ok: true,
      code: null,
      detail: boundedDetail(output.stdout, "Unblob external extractor check passed."),
      remediation: null,
      classification: "missing_dependency",
    };
  } catch (cause: unknown) {
    return probeFailureCheck(
      "external-dependencies",
      "extractor_dependency_unavailable",
      cause,
      "Install the external extractors reported by `unblob --show-external-dependencies`, then rerun rea doctor.",
      "missing_dependency",
    );
  }
};

const runProbe = (
  host: FirmwareDoctorHost,
  command: string,
  arguments_: readonly string[],
  environment: Readonly<NodeJS.ProcessEnv>,
): Promise<ProbeOutput> =>
  host.run(command, arguments_, {
    env: environment,
    timeout: PROBE_TIMEOUT_MS,
    maxBuffer: PROBE_OUTPUT_BYTES,
  });

const failedCheck = (
  name: string,
  code: string,
  detail: string,
  remediation: string,
  classification: DoctorProviderCheck["classification"],
): DoctorProviderCheck => ({
  name,
  ok: false,
  code,
  detail,
  remediation,
  classification,
});

const probeFailureCheck = (
  name: string,
  code: string,
  cause: unknown,
  remediation: string,
  classification: DoctorProviderCheck["classification"],
): DoctorProviderCheck => {
  const failure = execFileOutputFailure(cause);
  const output =
    failure === undefined
      ? ""
      : [failure.stdout, failure.stderr]
          .map((value) => value.trim())
          .filter((value) => value.length > 0)
          .join("\n");
  return failedCheck(
    name,
    code,
    boundedDetail(output, errorMessage(cause)),
    remediation,
    classification,
  );
};

const boundedDetail = (value: string, fallback: string): string => {
  const normalized = value.trim();
  const selected = normalized.length === 0 ? fallback : normalized;
  return selected.length <= 4096 ? selected : `${selected.slice(0, 4096)}…`;
};

const errorMessage = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

const systemFirmwareDoctorHost = (): FirmwareDoctorHost => ({
  platform: process.platform,
  processId: process.pid,
  resolveExecutable: async (path) => {
    const resolved = await realpath(path);
    await access(resolved, constants.R_OK | constants.X_OK);
    if (!(await stat(resolved)).isFile())
      throw new TypeError("Configured path is not a regular file");
    return resolved;
  },
  run: (command, arguments_, options) =>
    execFileOutput(command, arguments_, options),
});
