# AMD Hypervisor Detector

A Windows x64, AMD-only research tool for observing evidence of conventional and hidden SVM/NPT hypervisors. It combines safe user-mode checks with an optional read-only WDM probe and presents every conclusion with raw data, timing distributions, and limitations.

The tool reports virtualization evidence; it is not a malware classifier. Microsoft Hyper-V, VBS, Memory Integrity, Windows Sandbox, WSL2, and ordinary virtual machines are expected to produce `DETECTED` results.

## Highlights

- Native Windows x64 C++20 application with a Direct2D/DirectWrite dashboard.
- AMD vendor gate before AMD-specific interpretation.
- Modular `IDetectionTest` registry; tests do not depend on UI code.
- `PASS`, `SUSPICIOUS`, and `DETECTED` results with neutral `UNAVAILABLE`/`ERROR` operational states.
- Rerun-all, selected-test, and per-card Run controls.
- Expanded in-app reporting with verdict counts, confidence interpretation, per-test anomaly score/weight/reliability/duration, dynamically sized raw fields, driver ABI/state details, and an untruncated two-line report footer.
- Named timing distributions with count, median, average, P95, maximum, variance, standard deviation, quartiles, Tukey outliers, larger raw TSC-tick previews, and an on-screen histogram.
- Evidence-weighted confidence index. Direct indicators dominate; correlated timing/state families are capped and timing can never reach `DETECTED` by itself.
- Automatic atomic JSON reports under `%LOCALAPPDATA%\AmdHypervisorDetector\Reports`, plus Save As.
- Optional kdmapper-compatible driver with one versioned, fixed-size, `METHOD_BUFFERED`, read-only IOCTL.

## Checks

| Area | Observations |
|---|---|
| CPU gate | `AuthenticAMD`, brand, basic/extended CPUID ranges, x64 system view |
| Direct CPUID | `CPUID.1:ECX[31]`, coherent hypervisor vendor/max-leaf ranges, known VMM signatures |
| AMD SVM/NPT | SVM bit, Fn8000_000A revision, ASID count, NPT capability, internal consistency |
| Windows | Windows Hypervisor Platform runtime capability, active HVCI flags, VBS/HVCI/Credential Guard configuration, firmware virtualization and SLAT context |
| CPUID consistency | 256 repeated observations of deterministic feature leaves with per-CPU APIC bits excluded |
| User timing | Affinity-verified RDTSC/RDTSCP stability, serialized timer baseline, 4,096-sample CPUID distribution, rejected/migrated sample tracking, and an AMD SVM-leaf timing differential |
| Kernel AMD state | Mapper-safe CPL0 SVM/NPT CPUID view, CR0/CR3/CR4 x64 invariants, processor identity, and impossible feature combinations |
| Kernel serialized timing | Matching LFENCE/RDTSC and true RDTSCP-ended CPUID/baseline paths, raw tail analysis, AUX migration rejection, robust high-tail filtering, and conservative anomaly scoring |
| Kernel cross-core timing | 64 CPUID and 64 baseline samples on up to eight evenly selected, processor-group-aware logical CPUs; baseline-adjusted median spread, ratio, variance, and per-core raw distributions |
| Kernel phase differential | 256 order-balanced interleaved reference and bounded deterministic-local-work CPUID/baseline pairs, split-half repeatability, and absolute-plus-relative anomaly gates |
| Kernel SVM behavior | 32 repeated Fn8000_000A reads per representative core, SVM/NPT/ASID/revision determinism, and cross-core CPU-flag consistency |
| Cross-layer | Deterministic CPUID comparison between CPL3 and CPL0 on the exact processor reported by the driver, excluding legacy APIC-ID bits and reserved SVM-leaf output |

NPT is not directly visible from a guest. The NPT bit reports capability, not active use. Hidden-SVM/NPT research therefore combines capability coherence, selective SVM-leaf timing, CPL0/CPL3 parity, and control-state invariants. There is deliberately no universal “NPT detected by latency” threshold.

## Build

Prerequisites:

- Windows x64 on an AMD processor for runtime research.
- Visual Studio 2026 Community with Desktop C++.
- Windows SDK and WDK `10.0.28000.0` with the `WindowsKernelModeDriver10.0` toolset.

From PowerShell:

```powershell
cd C:\Users\User\Documents\GitHub\AmdHypervisorDetector
.\scripts\build.ps1 -Configuration Release
```

The script rebuilds the app, driver, and tests, runs the statistics/protocol tests, and stages:

```text
artifacts\Release\AmdHypervisorDetector.exe
artifacts\Release\AmdHvDetectorDriver.sys
```

It does not load, map, install, or sign the driver. The Visual Studio solution can also be built directly as `Release|x64` or `Debug|x64`.

## Run user-mode checks

Launch `AmdHypervisorDetector.exe` and accept the administrator UAC prompt. The executable requests elevation so the same run can open the administrator-only kernel probe when it is mapped. A complete run starts automatically; Run all and each test's Run control can repeat sampling.

Timing runs first use a guarded user-mode capability probe so a restricted or inconsistent RDTSC/RDTSCP view becomes `UNAVAILABLE` instead of terminating the app. Sampling then temporarily requests one processor-group affinity and `THREAD_PRIORITY_ABOVE_NORMAL`, rejects AUX-domain changes, and restores affinity/priority through scope guards. The UI remains responsive because sampling and report writing happen on a worker thread.

## Optional manually mapped driver

The driver is designed for a manual kdmapper workflow and does not require a service, INF, or SCM entry. Its PE entry point is explicitly linked as `DriverEntry`; it ignores mapper-supplied arguments, resolves `IoCreateDriver`, creates `\Device\AmdHvDetector`, and publishes `\\.\AmdHvDetector`.

Use this only on a test machine you control. kdmapper commonly relies on a vulnerable-driver technique that weakens the normal Windows driver trust boundary and may conflict with VBS, the vulnerable-driver blocklist, or endpoint security. This repository does not bundle or automate kdmapper and does not alter Windows security settings.

Typical lab sequence:

1. Build `Release|x64`.
2. From an elevated terminal, use a known-compatible, trusted kdmapper build to map `AmdHvDetectorDriver.sys` manually. **Do not use `--free`, and do not enable any option that frees or discards the live mapped image after entry returns.** The device dispatch routines remain inside those pages.
3. Run `AmdHypervisorDetector.exe` and accept its automatic administrator UAC prompt so it can open the device ACL.
4. Rerun all checks. The kernel and cross-layer cards should change from `UNAVAILABLE` to measured results.
5. Reboot the test system when finished. `DriverUnload` is intentionally `NULL`; reboot is the only supported cleanup path. External unmapping while handles or IRPs may exist is unsupported.

Protocol v3 is not compatible with a previously mapped v2 image. Because the mapper-oriented driver intentionally has no unload callback, reboot before mapping the new v3 `.sys`; do not attempt to replace the resident image in place. The UI reports this condition explicitly when Windows returns a revision mismatch.

Do not try to install this unsigned mapper-oriented image as a production Windows service. For production deployment, replace the manual entry path with a documented signed-driver lifecycle and a proper INF.

## Driver safety contract

The kernel target:

- runs its IOCTL at `PASSIVE_LEVEL`;
- accepts an exact protocol version/size, zero reserved fields, and a bounded nonzero sample count only;
- uses `METHOD_BUFFERED` and an administrator/system device ACL;
- reads only CPUID, CR0/CR3/CR4, fenced RDTSC/RDTSCP timing, and processor identity;
- deliberately performs no `RDMSR`, `WRMSR`, or exception-dependent instruction probe;
- samples at most eight representative logical processors with 64 paired CPUID/baseline observations each and restores affinity after every processor;
- bounds deterministic local work to a short integer-only preconditioning loop outside the timed interval;
- restores processor-group affinity on every supported path;
- never writes an MSR or control register;
- never executes `VMRUN`, `VMLOAD`, `VMSAVE`, `INVLPGA`, or a hypercall;
- never scans physical memory, page tables, kernel objects, IDT/GDT state, or arbitrary MSR ranges;
- never hooks, raises IRQL for sampling, disables interrupts, or broadcasts IPIs.

The no-MSR choice is intentional. x64 exception handling depends on registered unwind metadata, while common manual mappers do not register a mapped image as a normal kernel module. Treating a potentially faulting `RDMSR` as feature discovery could therefore bugcheck the system instead of reaching a handler. A future signed, normally loaded driver can add architecturally gated MSR observations under a different protocol; this mapper-oriented build does not.

## Result interpretation

- `DETECTED`: direct evidence, such as the CPUID hypervisor bit, a recognized coherent hypervisor interface, Windows reporting an active hypervisor/HVCI, or the same architectural hypervisor flag in the CPL0 CPUID view.
- `SUSPICIOUS`: indirect latency, architectural inconsistency, selective filtering, or partial state. Review raw data and repeat under a quiet, fixed-power test condition.
- `PASS`: no evidence observed by that check. It never means that absence has been proven.
- `UNAVAILABLE` / `ERROR`: operational states excluded from scoring, such as an unmapped driver.

The confidence value is an evidence index, not a statistical probability. Each new kernel probe also exposes a separate 0–100 anomaly score for that test. Correlated timing, CPUID-consistency, CPU-state, and Windows-policy families are capped before combination, and the strongest direct observation controls the overall verdict. All raw samples remain in the UI/report; only isolated high-tail values beyond a conservative MAD/absolute/relative cutoff are excluded from scoring, and poor retention or AUX migration reduces reliability.

## Reports

Every completed run is automatically written atomically as UTF-8 JSON. The report includes:

- schema/application version, run timestamp, mixed-snapshot marker, and per-test UTC capture times;
- CPU/Windows profile;
- overall verdict, confidence index, and interpretation;
- every test's source, verdict, anomaly score, duration, weight, reliability, explanation, and raw measurements;
- every named primary/comparison timing series, its full statistics, and its raw samples;
- explicit limitations.

The Save report button writes the same immutable result snapshot to a chosen local path.

## Add a test

1. Implement `IDetectionTest` in a new source file (or move an existing built-in class out of `DetectionEngine.cpp`).
2. Return stable metadata, a `TestResult`, raw measurements, and a conservative evidence contribution.
3. Register the class in `DetectionEngine::DetectionEngine()`.
4. Add the source to `App\AmdHypervisorDetector.vcxproj`.
5. Keep UI, JSON, and overall scoring unchanged; they consume the shared result model automatically.

Kernel additions must extend `Shared\DriverProtocol.h` with a new protocol version, exact layout assertions, and strict validation. Mapper-targeted additions must remain non-faulting and avoid state-changing operations.

## Limitations

- A sufficiently careful SVM hypervisor can present a coherent CPUID/control-state view and virtualize the TSC.
- CPUID timing is reported in TSC ticks, not assumed core-clock cycles, and varies with CPU family, microcode, SMI, power management, interrupts, DPCs, thermals, and system load.
- The mapper-safe driver intentionally omits direct SVM MSR/host-save/SEV-state observations; safety takes priority over probe depth.
- The multicore survey is deliberately bounded to eight representative logical processors rather than every processor; it is a low-disruption consistency sample, not a topology benchmark.
- Registry policy is configuration context, not proof that VBS launched.
- `PF_SECOND_LEVEL_ADDRESS_TRANSLATION` and Fn8000_000A.NP are hardware capabilities, not proof of active NPT.
- A single in-guest tool cannot provide an absolute proof of bare-metal execution.

Primary architectural references include the [AMD64 Architecture Programmer's Manual, Volume 2](https://docs.amd.com/api/khub/documents/sD1_QL~h4Afq2_tvzxqqSQ/content), [AMD CPUID specification](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24594.pdf), [Microsoft Hyper-V feature discovery](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery), and [Windows high-resolution timing guidance](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps).
