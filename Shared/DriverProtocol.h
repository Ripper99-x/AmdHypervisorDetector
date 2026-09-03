#pragma once

// Shared, fixed-width ABI between the x64 user-mode app and the WDM probe.
// The device exposes one read-only operation and intentionally has no generic
// MSR, control-register, physical-memory, or write primitive.

#if defined(_KERNEL_MODE)
#include <ntddk.h>
#define AHD_UINT8 UINT8
#define AHD_UINT16 UINT16
#define AHD_UINT32 UINT32
#define AHD_INT32 INT32
#define AHD_UINT64 UINT64
#else
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winioctl.h>
#include <stddef.h>
#include <stdint.h>
#define AHD_UINT8 uint8_t
#define AHD_UINT16 uint16_t
#define AHD_UINT32 uint32_t
#define AHD_INT32 int32_t
#define AHD_UINT64 uint64_t
#endif

#define AHD_PROTOCOL_VERSION 3u
#define AHD_DEVICE_NT_NAME L"\\Device\\AmdHvDetector"
#define AHD_DEVICE_DOS_NAME L"\\DosDevices\\AmdHvDetector"
#define AHD_DEVICE_WIN32_NAME L"\\\\.\\AmdHvDetector"

#define AHD_IOCTL_QUERY_REPORT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801u, METHOD_BUFFERED, FILE_READ_ACCESS)

#define AHD_CPUID_RECORD_COUNT 6u
#define AHD_MAX_KERNEL_TIMING_SAMPLES 256u
#define AHD_MAX_REPRESENTATIVE_CORES 8u
#define AHD_PER_CORE_TIMING_SAMPLES 64u
#define AHD_SVM_STABILITY_READS 32u

enum AHD_CPU_FLAGS {
    AHD_CPU_FLAG_AMD = 1u << 0,
    AHD_CPU_FLAG_HYPERVISOR = 1u << 1,
    AHD_CPU_FLAG_SVM = 1u << 2,
    AHD_CPU_FLAG_NPT = 1u << 3,
    AHD_CPU_FLAG_RDTSCP = 1u << 4
};

enum AHD_PROBE_FLAGS {
    // Manual mappers do not register x64 unwind metadata with the kernel.
    // This build therefore performs no exception-dependent RDMSR probes.
    AHD_PROBE_FLAG_MAPPER_SAFE = 1u << 0,
    AHD_PROBE_FLAG_MSR_READS_SKIPPED = 1u << 1,
    AHD_PROBE_FLAG_RDTSC_TIMING = 1u << 2,
    AHD_PROBE_FLAG_RDTSCP_TIMING = 1u << 3,
    AHD_PROBE_FLAG_STRESS_TIMING = 1u << 4,
    AHD_PROBE_FLAG_MULTICORE_TIMING = 1u << 5,
    AHD_PROBE_FLAG_SVM_STABILITY = 1u << 6
};

enum AHD_CORE_PROBE_FLAGS {
    AHD_CORE_FLAG_AFFINITY_CONFIRMED = 1u << 0,
    AHD_CORE_FLAG_RDTSCP_SUPPORTED = 1u << 1,
    AHD_CORE_FLAG_AUX_STABLE = 1u << 2,
    AHD_CORE_FLAG_SVM_LEAF_AVAILABLE = 1u << 3,
    AHD_CORE_FLAG_SVM_LEAF_STABLE = 1u << 4,
    AHD_CORE_FLAG_STATE_MATCHES_PRIMARY = 1u << 5,
    AHD_CORE_FLAG_TIMING_COMPLETE = 1u << 6
};

#pragma pack(push, 8)

typedef struct AHD_CPUID_RECORD {
    AHD_UINT32 Leaf;
    AHD_UINT32 Subleaf;
    AHD_INT32 Eax;
    AHD_INT32 Ebx;
    AHD_INT32 Ecx;
    AHD_INT32 Edx;
} AHD_CPUID_RECORD;

typedef struct AHD_QUERY_REQUEST {
    AHD_UINT32 Size;
    AHD_UINT32 Version;
    AHD_UINT32 RequestedTimingSamples;
    AHD_UINT32 Reserved;
} AHD_QUERY_REQUEST;

typedef struct AHD_CORE_TIMING_RECORD {
    AHD_UINT16 ProcessorGroup;
    AHD_UINT8 ProcessorNumber;
    AHD_UINT8 CoreFlags;
    AHD_UINT32 CpuFlags;

    AHD_UINT32 CpuidSampleCount;
    AHD_UINT32 CpuidRejectedCount;
    AHD_UINT32 BaselineSampleCount;
    AHD_UINT32 BaselineRejectedCount;
    AHD_UINT32 SvmLeafReadCount;
    AHD_UINT32 SvmLeafMismatchCount;
    AHD_UINT32 RdtscpAux;
    AHD_UINT32 RdtscpAuxMismatchCount;

    AHD_CPUID_RECORD SvmLeaf;
    AHD_UINT64 CpuidCycles[AHD_PER_CORE_TIMING_SAMPLES];
    AHD_UINT64 BaselineCycles[AHD_PER_CORE_TIMING_SAMPLES];
} AHD_CORE_TIMING_RECORD;

typedef struct AHD_KERNEL_REPORT {
    AHD_UINT32 Size;
    AHD_UINT32 Version;
    AHD_INT32 OperationStatus;
    AHD_UINT32 CpuFlags;

    AHD_UINT16 ProcessorGroup;
    AHD_UINT8 ProcessorNumber;
    AHD_UINT8 Reserved0;
    AHD_UINT32 ProbeFlags;
    AHD_UINT32 Reserved1;

    AHD_UINT64 Cr0;
    AHD_UINT64 Cr3;
    AHD_UINT64 Cr4;

    AHD_CPUID_RECORD Cpuid[AHD_CPUID_RECORD_COUNT];

    AHD_UINT32 TimingSampleCount;
    AHD_UINT32 SvmTimingSampleCount;
    AHD_UINT32 TimingRejectedCount;
    AHD_UINT32 Reserved2;
    AHD_UINT64 CpuidCycles[AHD_MAX_KERNEL_TIMING_SAMPLES];
    AHD_UINT64 SvmCpuidCycles[AHD_MAX_KERNEL_TIMING_SAMPLES];
    AHD_UINT64 BaselineCycles[AHD_MAX_KERNEL_TIMING_SAMPLES];

    // RDTSCP-ended measurements use a matching empty path and reject samples
    // when IA32_TSC_AUX changes between the pre-sample and end timestamps.
    AHD_UINT32 RdtscpCpuidSampleCount;
    AHD_UINT32 RdtscpCpuidRejectedCount;
    AHD_UINT32 RdtscpBaselineSampleCount;
    AHD_UINT32 RdtscpBaselineRejectedCount;
    AHD_UINT32 RdtscpAuxMismatchCount;

    // The stressed series alternates the same two timed paths after bounded,
    // deterministic integer work. Work itself is outside the timed interval.
    AHD_UINT32 StressCpuidSampleCount;
    AHD_UINT32 StressCpuidRejectedCount;
    AHD_UINT32 StressBaselineSampleCount;
    AHD_UINT32 StressBaselineRejectedCount;
    AHD_UINT32 StressAuxMismatchCount;

    AHD_UINT32 CoreRecordCount;
    AHD_UINT32 LogicalProcessorCount;

    AHD_UINT64 RdtscpCpuidCycles[AHD_MAX_KERNEL_TIMING_SAMPLES];
    AHD_UINT64 RdtscpBaselineCycles[AHD_MAX_KERNEL_TIMING_SAMPLES];
    AHD_UINT64 StressCpuidCycles[AHD_MAX_KERNEL_TIMING_SAMPLES];
    AHD_UINT64 StressBaselineCycles[AHD_MAX_KERNEL_TIMING_SAMPLES];
    AHD_CORE_TIMING_RECORD CoreTimings[AHD_MAX_REPRESENTATIVE_CORES];
} AHD_KERNEL_REPORT;

#pragma pack(pop)

#if defined(__cplusplus)
static_assert(sizeof(AHD_CPUID_RECORD) == 24u, "AHD_CPUID_RECORD ABI changed");
static_assert(sizeof(AHD_QUERY_REQUEST) == 16u, "AHD_QUERY_REQUEST ABI changed");
static_assert(offsetof(AHD_CORE_TIMING_RECORD, SvmLeaf) == 40u,
              "AHD_CORE_TIMING_RECORD.SvmLeaf offset changed");
static_assert(offsetof(AHD_CORE_TIMING_RECORD, CpuidCycles) == 64u,
              "AHD_CORE_TIMING_RECORD.CpuidCycles offset changed");
static_assert(offsetof(AHD_CORE_TIMING_RECORD, BaselineCycles) == 576u,
              "AHD_CORE_TIMING_RECORD.BaselineCycles offset changed");
static_assert(sizeof(AHD_CORE_TIMING_RECORD) == 1088u,
              "AHD_CORE_TIMING_RECORD ABI changed");
static_assert(offsetof(AHD_KERNEL_REPORT, Cr0) == 32u, "AHD_KERNEL_REPORT.Cr0 offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, Cpuid) == 56u, "AHD_KERNEL_REPORT.Cpuid offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, TimingSampleCount) == 200u,
              "AHD_KERNEL_REPORT timing header offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, CpuidCycles) == 216u,
              "AHD_KERNEL_REPORT.CpuidCycles offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, SvmCpuidCycles) == 2264u,
              "AHD_KERNEL_REPORT.SvmCpuidCycles offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, BaselineCycles) == 4312u,
              "AHD_KERNEL_REPORT.BaselineCycles offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, RdtscpCpuidSampleCount) == 6360u,
              "AHD_KERNEL_REPORT RDTSCP header offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, CoreRecordCount) == 6400u,
              "AHD_KERNEL_REPORT.CoreRecordCount offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, RdtscpCpuidCycles) == 6408u,
              "AHD_KERNEL_REPORT.RdtscpCpuidCycles offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, RdtscpBaselineCycles) == 8456u,
              "AHD_KERNEL_REPORT.RdtscpBaselineCycles offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, StressCpuidCycles) == 10504u,
              "AHD_KERNEL_REPORT.StressCpuidCycles offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, StressBaselineCycles) == 12552u,
              "AHD_KERNEL_REPORT.StressBaselineCycles offset changed");
static_assert(offsetof(AHD_KERNEL_REPORT, CoreTimings) == 14600u,
              "AHD_KERNEL_REPORT.CoreTimings offset changed");
static_assert(sizeof(AHD_KERNEL_REPORT) == 23304u, "AHD_KERNEL_REPORT ABI changed");
static_assert(sizeof(AHD_KERNEL_REPORT) < 65536u, "AHD_KERNEL_REPORT must remain below 64 KiB");
#elif defined(_KERNEL_MODE)
C_ASSERT(sizeof(AHD_CPUID_RECORD) == 24u);
C_ASSERT(sizeof(AHD_QUERY_REQUEST) == 16u);
C_ASSERT(FIELD_OFFSET(AHD_CORE_TIMING_RECORD, SvmLeaf) == 40u);
C_ASSERT(FIELD_OFFSET(AHD_CORE_TIMING_RECORD, CpuidCycles) == 64u);
C_ASSERT(FIELD_OFFSET(AHD_CORE_TIMING_RECORD, BaselineCycles) == 576u);
C_ASSERT(sizeof(AHD_CORE_TIMING_RECORD) == 1088u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, Cr0) == 32u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, Cpuid) == 56u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, TimingSampleCount) == 200u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, CpuidCycles) == 216u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, SvmCpuidCycles) == 2264u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, BaselineCycles) == 4312u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, RdtscpCpuidSampleCount) == 6360u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, CoreRecordCount) == 6400u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, RdtscpCpuidCycles) == 6408u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, RdtscpBaselineCycles) == 8456u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, StressCpuidCycles) == 10504u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, StressBaselineCycles) == 12552u);
C_ASSERT(FIELD_OFFSET(AHD_KERNEL_REPORT, CoreTimings) == 14600u);
C_ASSERT(sizeof(AHD_KERNEL_REPORT) == 23304u);
C_ASSERT(sizeof(AHD_KERNEL_REPORT) < 65536u);
#endif

#undef AHD_UINT8
#undef AHD_UINT16
#undef AHD_UINT32
#undef AHD_INT32
#undef AHD_UINT64
