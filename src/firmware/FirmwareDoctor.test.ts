import { describe, expect, it } from "vitest";

import {
  inspectFirmwareProviders,
  type FirmwareDoctorHost,
} from "./FirmwareDoctor.js";

const output = (stdout: string, stderr = "") => ({
  stdout,
  stderr,
  stdoutBytes: Buffer.byteLength(stdout),
  stderrBytes: Buffer.byteLength(stderr),
});

const failedProbe = (stderr: string, code = 1): Error => {
  const failure = new Error(stderr);
  Reflect.set(failure, "stdout", "");
  Reflect.set(failure, "stderr", stderr);
  Reflect.set(failure, "code", code);
  Reflect.set(failure, "signal", null);
  Reflect.set(failure, "killed", false);
  Reflect.set(failure, "outputTruncated", false);
  return failure;
};

const environment = {
  REA_BINWALK_COMMAND: "/tools/binwalk",
  REA_UNBLOB_COMMAND: "/tools/unblob",
  REA_FIRMWARE_PRLIMIT_COMMAND: "/tools/prlimit",
};

const healthyHost = (
  overrides: Partial<FirmwareDoctorHost> = {},
): FirmwareDoctorHost => ({
  platform: "linux",
  processId: 4242,
  resolveExecutable: (path) => Promise.resolve(path),
  run: (command, arguments_) => {
    if (command === "ps")
      return Promise.resolve(
        output(" 4242 1 4242 1000 S node rea\n 5000 4242 4242 1000 S helper\n"),
      );
    if (command === "/tools/binwalk" && arguments_[0] === "--version")
      return Promise.resolve(output("binwalk 3.1.0\n"));
    if (command === "/tools/unblob" && arguments_[0] === "--version")
      return Promise.resolve(output("26.6.4\n"));
    if (
      command === "/tools/unblob" &&
      arguments_[0] === "--show-external-dependencies"
    )
      return Promise.resolve(output("7z ✓\ndebugfs ✓\n"));
    return Promise.reject(new Error(`Unexpected probe: ${command}`));
  },
  ...overrides,
});

describe("firmware doctor", () => {
  it("reports configured firmware engines as available when readiness probes pass", async () => {
    const inspections = await inspectFirmwareProviders(
      environment,
      healthyHost(),
    );

    expect(inspections).toHaveLength(2);
    expect(inspections.map(({ id }) => id)).toEqual(["binwalk", "unblob"]);
    expect(inspections.every(({ configured }) => configured)).toBe(true);
    expect(inspections.every(({ available }) => available)).toBe(true);
    expect(inspections.map(({ providerVersion }) => providerVersion)).toEqual([
      "3.1.0",
      "26.6.4",
    ]);
    expect(
      inspections
        .flatMap(({ checks }) => checks)
        .filter(({ name }) => name === "process-ownership")
        .every(({ ok }) => ok),
    ).toBe(true);
    expect(
      inspections
        .find(({ id }) => id === "unblob")
        ?.checks.find(({ name }) => name === "external-dependencies"),
    ).toMatchObject({ ok: true, code: null });
  });

  it("reports missing Unblob extractors without hiding the engine version", async () => {
    const host = healthyHost({
      run: async (command, arguments_, options) => {
        if (
          command === "/tools/unblob" &&
          arguments_[0] === "--show-external-dependencies"
        )
          throw failedProbe("sasquatch ✗");
        return healthyHost().run(command, arguments_, options);
      },
    });

    const inspections = await inspectFirmwareProviders(environment, host);
    const unblob = inspections.find(({ id }) => id === "unblob");

    expect(unblob).toMatchObject({
      configured: true,
      available: false,
      providerVersion: "26.6.4",
    });
    expect(
      unblob?.checks.find(({ name }) => name === "external-dependencies"),
    ).toMatchObject({
      ok: false,
      code: "extractor_dependency_unavailable",
      classification: "missing_dependency",
      detail: "sasquatch ✗",
    });
  });

  it("rejects an unsupported firmware release line", async () => {
    const host = healthyHost({
      run: (command, arguments_, options) =>
        command === "/tools/binwalk" && arguments_[0] === "--version"
          ? Promise.resolve(output("binwalk 4.0.0\n"))
          : healthyHost().run(command, arguments_, options),
    });

    const inspections = await inspectFirmwareProviders(environment, host);
    const binwalk = inspections.find(({ id }) => id === "binwalk");

    expect(binwalk).toMatchObject({
      configured: true,
      available: false,
      providerVersion: null,
    });
    expect(binwalk?.checks.find(({ name }) => name === "version")).toMatchObject(
      {
        ok: false,
        code: "unsupported_version",
        classification: "config_drift",
      },
    );
  });

  it("reports Linux as a prerequisite without running firmware probes on another host", async () => {
    const calls: string[] = [];
    const host = healthyHost({
      platform: "darwin",
      run: (command) => {
        calls.push(command);
        return Promise.reject(new Error("probe should not run"));
      },
    });

    const inspections = await inspectFirmwareProviders(environment, host);

    expect(inspections.every(({ available }) => !available)).toBe(true);
    expect(
      inspections.every(
        ({ checks }) =>
          checks.find(({ name }) => name === "platform")?.classification ===
          "unsupported_host",
      ),
    ).toBe(true);
    expect(calls).toEqual([]);
  });

  it("keeps unconfigured firmware engines optional while explaining configuration", async () => {
    const inspections = await inspectFirmwareProviders({}, healthyHost());

    expect(inspections.every(({ configured }) => !configured)).toBe(true);
    expect(inspections.every(({ available }) => !available)).toBe(true);
    expect(
      inspections.map(({ checks }) =>
        checks.find(({ name }) => name === "configuration")?.code,
      ),
    ).toEqual(["not_configured", "not_configured"]);
  });
});
