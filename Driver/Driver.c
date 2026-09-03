#include <ntddk.h>
#include <wdmsec.h>
#include <intrin.h>

#include "../Shared/DriverProtocol.h"

typedef NTSTATUS (*AHD_IO_CREATE_DRIVER)(
    _In_opt_ PUNICODE_STRING DriverName,
    _In_ PDRIVER_INITIALIZE InitializationFunction);

static DRIVER_INITIALIZE AhdInitialize;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_CLEANUP)
static DRIVER_DISPATCH AhdCreateClose;
static DRIVER_DISPATCH AhdUnsupported;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static DRIVER_DISPATCH AhdDeviceControl;
DRIVER_INITIALIZE DriverEntry;

static const GUID AHD_DEVICE_CLASS_GUID =
    {0x00da07b4, 0x6d53, 0x416d, {0xb3, 0x55, 0x7a, 0xe9, 0x31, 0xab, 0x80, 0x15}};

static KMUTEX AhdProbeMutex;

static NTSTATUS AhdCompleteIrp(
    _Inout_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static VOID AhdReadCpuid(
    _Out_ AHD_CPUID_RECORD* Record,
    _In_ UINT32 Leaf,
    _In_ UINT32 Subleaf)
{
    int registers[4] = {0};
    __cpuidex(registers, (int)Leaf, (int)Subleaf);
    Record->Leaf = Leaf;
    Record->Subleaf = Subleaf;
    Record->Eax = registers[0];
    Record->Ebx = registers[1];
    Record->Ecx = registers[2];
    Record->Edx = registers[3];
}

static BOOLEAN AhdIsAuthenticAmd(_In_ const AHD_CPUID_RECORD* Leaf0)
{
    const UINT32 authentic = 0x68747541u; // "Auth"
    const UINT32 entic = 0x69746e65u;     // "enti"
    const UINT32 amd = 0x444d4163u;       // "cAMD"
    return (UINT32)Leaf0->Ebx == authentic &&
           (UINT32)Leaf0->Edx == entic &&
           (UINT32)Leaf0->Ecx == amd;
}

static BOOLEAN AhdCpuidEqual(
    _In_ const AHD_CPUID_RECORD* Left,
    _In_ const AHD_CPUID_RECORD* Right)
{
    return Left->Leaf == Right->Leaf &&
           Left->Subleaf == Right->Subleaf &&
           Left->Eax == Right->Eax &&
           Left->Ebx == Right->Ebx &&
           Left->Ecx == Right->Ecx &&
           Left->Edx == Right->Edx;
}

static UINT32 AhdQueryCpuFlags(
    _Out_opt_ AHD_CPUID_RECORD* SvmLeaf,
    _Out_opt_ UINT32* ExtendedMaximum)
{
    AHD_CPUID_RECORD leaf0;
    AHD_CPUID_RECORD leaf1;
    AHD_CPUID_RECORD extendedLeaf;
    AHD_CPUID_RECORD featureLeaf;
    AHD_CPUID_RECORD localSvmLeaf;
    UINT32 flags = 0;
    UINT32 extendedMaximum = 0;

    RtlZeroMemory(&leaf0, sizeof(leaf0));
    RtlZeroMemory(&leaf1, sizeof(leaf1));
    RtlZeroMemory(&extendedLeaf, sizeof(extendedLeaf));
    RtlZeroMemory(&featureLeaf, sizeof(featureLeaf));
    RtlZeroMemory(&localSvmLeaf, sizeof(localSvmLeaf));

    AhdReadCpuid(&leaf0, 0u, 0u);
    if (!AhdIsAuthenticAmd(&leaf0)) {
        if (SvmLeaf != NULL) {
            *SvmLeaf = localSvmLeaf;
        }
        if (ExtendedMaximum != NULL) {
            *ExtendedMaximum = 0;
        }
        return 0;
    }

    flags |= AHD_CPU_FLAG_AMD;
    if ((UINT32)leaf0.Eax >= 1u) {
        AhdReadCpuid(&leaf1, 1u, 0u);
        if (((UINT32)leaf1.Ecx & (1u << 31)) != 0) {
            flags |= AHD_CPU_FLAG_HYPERVISOR;
        }
    }

    AhdReadCpuid(&extendedLeaf, 0x80000000u, 0u);
    extendedMaximum = (UINT32)extendedLeaf.Eax;
    if (extendedMaximum >= 0x80000001u) {
        AhdReadCpuid(&featureLeaf, 0x80000001u, 0u);
        if (((UINT32)featureLeaf.Ecx & (1u << 2)) != 0) {
            flags |= AHD_CPU_FLAG_SVM;
        }
        if (((UINT32)featureLeaf.Edx & (1u << 27)) != 0) {
            flags |= AHD_CPU_FLAG_RDTSCP;
        }
    }

    if ((flags & AHD_CPU_FLAG_SVM) != 0 && extendedMaximum >= 0x8000000Au) {
        AhdReadCpuid(&localSvmLeaf, 0x8000000Au, 0u);
        if (((UINT32)localSvmLeaf.Edx & 1u) != 0) {
            flags |= AHD_CPU_FLAG_NPT;
        }
    }

    if (SvmLeaf != NULL) {
        *SvmLeaf = localSvmLeaf;
    }
    if (ExtendedMaximum != NULL) {
        *ExtendedMaximum = extendedMaximum;
    }
    return flags;
}

static BOOLEAN AhdMeasureRdtscpPath(
    _In_ BOOLEAN ExecuteCpuid,
    _Out_ UINT64* Delta,
    _Out_ UINT32* ObservedAux,
    _Out_ BOOLEAN* AuxMismatch)
{
    unsigned int beginAux = 0;
    unsigned int endAux = 0;
    UINT64 begin;
    UINT64 end;
    int registers[4] = {0};

    *Delta = 0;
    *ObservedAux = 0;
    *AuxMismatch = FALSE;

    (void)__rdtscp(&beginAux);
    _mm_lfence();
    begin = __rdtsc();
    if (ExecuteCpuid) {
        __cpuidex(registers, 0, 0);
    }
    end = __rdtscp(&endAux);
    _mm_lfence();

    if (beginAux != endAux) {
        *AuxMismatch = TRUE;
        return FALSE;
    }
    if (end < begin) {
        return FALSE;
    }

    *Delta = end - begin;
    *ObservedAux = endAux;
    return TRUE;
}

static VOID AhdRunDeterministicLocalWork(_Inout_ volatile UINT64* State)
{
    UINT32 iteration;
    UINT64 value = *State;

    for (iteration = 0; iteration < 256u; ++iteration) {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        value += 0x9E3779B97F4A7C15ull + (UINT64)iteration;
    }
    *State = value;
}

static VOID AhdStoreRdtscpSample(
    _In_ BOOLEAN ExecuteCpuid,
    _Inout_updates_(Capacity) UINT64* Samples,
    _In_ UINT32 Capacity,
    _Inout_ UINT32* AcceptedCount,
    _Inout_ UINT32* RejectedCount,
    _Inout_ UINT32* AuxMismatchCount)
{
    UINT64 delta;
    UINT32 observedAux;
    BOOLEAN auxMismatch;

    if (AhdMeasureRdtscpPath(
            ExecuteCpuid,
            &delta,
            &observedAux,
            &auxMismatch) && *AcceptedCount < Capacity) {
        Samples[*AcceptedCount] = delta;
        ++(*AcceptedCount);
    } else {
        ++(*RejectedCount);
        if (auxMismatch) {
            ++(*AuxMismatchCount);
        }
    }
}

static VOID AhdCollectConditionedTiming(
    _Inout_ AHD_KERNEL_REPORT* Report,
    _In_ UINT32 RequestedSamples)
{
    UINT32 sample;
    int registers[4] = {0};
    volatile UINT64 workState = 0xA0761D6478BD642Full;

    for (sample = 0; sample < 32u; ++sample) {
        UINT64 delta;
        UINT32 observedAux;
        BOOLEAN auxMismatch;
        __cpuidex(registers, 0, 0);
        (void)AhdMeasureRdtscpPath(TRUE, &delta, &observedAux, &auxMismatch);
    }

    for (sample = 0; sample < RequestedSamples; ++sample) {
        if ((sample & 1u) == 0) {
            AhdStoreRdtscpSample(
                TRUE,
                Report->RdtscpCpuidCycles,
                AHD_MAX_KERNEL_TIMING_SAMPLES,
                &Report->RdtscpCpuidSampleCount,
                &Report->RdtscpCpuidRejectedCount,
                &Report->RdtscpAuxMismatchCount);
            AhdStoreRdtscpSample(
                FALSE,
                Report->RdtscpBaselineCycles,
                AHD_MAX_KERNEL_TIMING_SAMPLES,
                &Report->RdtscpBaselineSampleCount,
                &Report->RdtscpBaselineRejectedCount,
                &Report->RdtscpAuxMismatchCount);
            AhdRunDeterministicLocalWork(&workState);
            AhdStoreRdtscpSample(
                TRUE,
                Report->StressCpuidCycles,
                AHD_MAX_KERNEL_TIMING_SAMPLES,
                &Report->StressCpuidSampleCount,
                &Report->StressCpuidRejectedCount,
                &Report->StressAuxMismatchCount);
            AhdRunDeterministicLocalWork(&workState);
            AhdStoreRdtscpSample(
                FALSE,
                Report->StressBaselineCycles,
                AHD_MAX_KERNEL_TIMING_SAMPLES,
                &Report->StressBaselineSampleCount,
                &Report->StressBaselineRejectedCount,
                &Report->StressAuxMismatchCount);
        } else {
            AhdRunDeterministicLocalWork(&workState);
            AhdStoreRdtscpSample(
                FALSE,
                Report->StressBaselineCycles,
                AHD_MAX_KERNEL_TIMING_SAMPLES,
                &Report->StressBaselineSampleCount,
                &Report->StressBaselineRejectedCount,
                &Report->StressAuxMismatchCount);
            AhdRunDeterministicLocalWork(&workState);
            AhdStoreRdtscpSample(
                TRUE,
                Report->StressCpuidCycles,
                AHD_MAX_KERNEL_TIMING_SAMPLES,
                &Report->StressCpuidSampleCount,
                &Report->StressCpuidRejectedCount,
                &Report->StressAuxMismatchCount);
            AhdStoreRdtscpSample(
                FALSE,
                Report->RdtscpBaselineCycles,
                AHD_MAX_KERNEL_TIMING_SAMPLES,
                &Report->RdtscpBaselineSampleCount,
                &Report->RdtscpBaselineRejectedCount,
                &Report->RdtscpAuxMismatchCount);
            AhdStoreRdtscpSample(
                TRUE,
                Report->RdtscpCpuidCycles,
                AHD_MAX_KERNEL_TIMING_SAMPLES,
                &Report->RdtscpCpuidSampleCount,
                &Report->RdtscpCpuidRejectedCount,
                &Report->RdtscpAuxMismatchCount);
        }
    }
}

static VOID AhdSampleSvmLeaf(
    _Inout_ AHD_CORE_TIMING_RECORD* Core,
    _In_ UINT32 ReadCount)
{
    UINT32 index;

    for (index = 0; index < ReadCount; ++index) {
        AHD_CPUID_RECORD current;
        AhdReadCpuid(&current, 0x8000000Au, 0u);
        if (Core->SvmLeafReadCount == 0) {
            Core->SvmLeaf = current;
        } else if (!AhdCpuidEqual(&Core->SvmLeaf, &current)) {
            ++Core->SvmLeafMismatchCount;
        }
        ++Core->SvmLeafReadCount;
    }
}

static VOID AhdStoreCoreSample(
    _Inout_ AHD_CORE_TIMING_RECORD* Core,
    _In_ BOOLEAN ExecuteCpuid)
{
    UINT64 delta;
    UINT32 observedAux;
    BOOLEAN auxMismatch;
    UINT32* acceptedCount = ExecuteCpuid
        ? &Core->CpuidSampleCount
        : &Core->BaselineSampleCount;
    UINT32* rejectedCount = ExecuteCpuid
        ? &Core->CpuidRejectedCount
        : &Core->BaselineRejectedCount;
    UINT64* samples = ExecuteCpuid
        ? Core->CpuidCycles
        : Core->BaselineCycles;
    const UINT32 priorAccepted = Core->CpuidSampleCount + Core->BaselineSampleCount;

    if (!AhdMeasureRdtscpPath(
            ExecuteCpuid,
            &delta,
            &observedAux,
            &auxMismatch)) {
        ++(*rejectedCount);
        if (auxMismatch) {
            ++Core->RdtscpAuxMismatchCount;
        }
        return;
    }

    if (priorAccepted == 0) {
        Core->RdtscpAux = observedAux;
    } else if (Core->RdtscpAux != observedAux) {
        ++Core->RdtscpAuxMismatchCount;
    }

    if (*acceptedCount < AHD_PER_CORE_TIMING_SAMPLES) {
        samples[*acceptedCount] = delta;
        ++(*acceptedCount);
    } else {
        ++(*rejectedCount);
    }
}

static VOID AhdCollectCoreTiming(
    _Inout_ AHD_CORE_TIMING_RECORD* Core,
    _In_ const AHD_KERNEL_REPORT* Report)
{
    UINT32 extendedMaximum;
    UINT32 sample;
    int registers[4] = {0};

    Core->CpuFlags = AhdQueryCpuFlags(NULL, &extendedMaximum);
    if ((Core->CpuFlags & AHD_CPU_FLAG_RDTSCP) != 0) {
        Core->CoreFlags |= AHD_CORE_FLAG_RDTSCP_SUPPORTED;
    }
    if ((Core->CpuFlags & AHD_CPU_FLAG_SVM) != 0 &&
        extendedMaximum >= 0x8000000Au) {
        Core->CoreFlags |= AHD_CORE_FLAG_SVM_LEAF_AVAILABLE;
        AhdSampleSvmLeaf(Core, AHD_SVM_STABILITY_READS / 2u);
    }

    if ((Core->CpuFlags & AHD_CPU_FLAG_RDTSCP) != 0) {
        for (sample = 0; sample < 32u; ++sample) {
            __cpuidex(registers, 0, 0);
        }
        for (sample = 0; sample < AHD_PER_CORE_TIMING_SAMPLES; ++sample) {
            if ((sample & 1u) == 0) {
                AhdStoreCoreSample(Core, TRUE);
                AhdStoreCoreSample(Core, FALSE);
            } else {
                AhdStoreCoreSample(Core, FALSE);
                AhdStoreCoreSample(Core, TRUE);
            }
        }
    }

    if ((Core->CoreFlags & AHD_CORE_FLAG_SVM_LEAF_AVAILABLE) != 0) {
        AhdSampleSvmLeaf(Core, AHD_SVM_STABILITY_READS / 2u);
        if (Core->SvmLeafReadCount == AHD_SVM_STABILITY_READS &&
            Core->SvmLeafMismatchCount == 0) {
            Core->CoreFlags |= AHD_CORE_FLAG_SVM_LEAF_STABLE;
        }
    }

    if (Core->CpuFlags == Report->CpuFlags &&
        (((Core->CoreFlags & AHD_CORE_FLAG_SVM_LEAF_AVAILABLE) == 0) ||
         AhdCpuidEqual(&Core->SvmLeaf, &Report->Cpuid[4]))) {
        Core->CoreFlags |= AHD_CORE_FLAG_STATE_MATCHES_PRIMARY;
    }
    if (Core->CpuidSampleCount == AHD_PER_CORE_TIMING_SAMPLES &&
        Core->BaselineSampleCount == AHD_PER_CORE_TIMING_SAMPLES) {
        Core->CoreFlags |= AHD_CORE_FLAG_TIMING_COMPLETE;
    }
    if (Core->RdtscpAuxMismatchCount == 0 &&
        Core->CpuidSampleCount != 0 && Core->BaselineSampleCount != 0) {
        Core->CoreFlags |= AHD_CORE_FLAG_AUX_STABLE;
    }
}

static VOID AhdCollectRepresentativeCores(_Inout_ AHD_KERNEL_REPORT* Report)
{
    ULONG totalProcessors;
    ULONG selectedProcessors;
    ULONG selectedIndex;

    totalProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    Report->LogicalProcessorCount = totalProcessors;
    selectedProcessors = totalProcessors < AHD_MAX_REPRESENTATIVE_CORES
        ? totalProcessors
        : AHD_MAX_REPRESENTATIVE_CORES;

    for (selectedIndex = 0; selectedIndex < selectedProcessors; ++selectedIndex) {
        const ULONG processorIndex = selectedProcessors <= 1u
            ? 0u
            : (selectedIndex * (totalProcessors - 1u)) / (selectedProcessors - 1u);
        PROCESSOR_NUMBER requestedProcessor;
        PROCESSOR_NUMBER actualProcessor;
        GROUP_AFFINITY requestedAffinity;
        GROUP_AFFINITY previousAffinity;
        AHD_CORE_TIMING_RECORD* core = &Report->CoreTimings[Report->CoreRecordCount];
        BOOLEAN affinitySet = FALSE;

        RtlZeroMemory(core, sizeof(*core));
        RtlZeroMemory(&requestedProcessor, sizeof(requestedProcessor));
        RtlZeroMemory(&actualProcessor, sizeof(actualProcessor));
        RtlZeroMemory(&requestedAffinity, sizeof(requestedAffinity));
        RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));

        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(processorIndex, &requestedProcessor)) ||
            requestedProcessor.Number >= sizeof(KAFFINITY) * 8u) {
            continue;
        }

        core->ProcessorGroup = requestedProcessor.Group;
        core->ProcessorNumber = requestedProcessor.Number;
        ++Report->CoreRecordCount;

        requestedAffinity.Group = requestedProcessor.Group;
        requestedAffinity.Mask = ((KAFFINITY)1) << requestedProcessor.Number;
        KeSetSystemGroupAffinityThread(&requestedAffinity, &previousAffinity);
        affinitySet = TRUE;
        KeGetCurrentProcessorNumberEx(&actualProcessor);

        if (actualProcessor.Group == requestedProcessor.Group &&
            actualProcessor.Number == requestedProcessor.Number) {
            core->CoreFlags |= AHD_CORE_FLAG_AFFINITY_CONFIRMED;
            AhdCollectCoreTiming(core, Report);
        }

        if (affinitySet) {
            KeRevertToUserGroupAffinityThread(&previousAffinity);
        }
    }
}

static UINT64 AhdBeginTsc(VOID)
{
    _mm_lfence();
    return __rdtsc();
}

static UINT64 AhdEndTsc(VOID)
{
    _mm_lfence();
    {
        const UINT64 value = __rdtsc();
        _mm_lfence();
        return value;
    }
}

static VOID AhdCollectTiming(
    _Inout_ AHD_KERNEL_REPORT* Report,
    _In_ UINT32 RequestedSamples)
{
    UINT32 sample;
    UINT32 accepted = 0;
    int registers[4] = {0};
    const BOOLEAN svmLeafAvailable =
        (Report->CpuFlags & AHD_CPU_FLAG_SVM) != 0 &&
        (UINT32)Report->Cpuid[2].Eax >= 0x8000000Au;

    if (RequestedSamples == 0) {
        return;
    }

    for (sample = 0; sample < 96; ++sample) {
        __cpuidex(registers, 0, 0);
    }

    for (sample = 0; sample < RequestedSamples; ++sample) {
        const UINT64 begin = AhdBeginTsc();
        __cpuidex(registers, 0, 0);
        {
            const UINT64 end = AhdEndTsc();
            if (end >= begin && accepted < AHD_MAX_KERNEL_TIMING_SAMPLES) {
                Report->CpuidCycles[accepted] = end - begin;
                ++accepted;
            } else {
                ++Report->TimingRejectedCount;
            }
        }
    }

    Report->TimingSampleCount = accepted;
    if (svmLeafAvailable) {
        accepted = 0;
        for (sample = 0; sample < RequestedSamples; ++sample) {
            const UINT64 begin = AhdBeginTsc();
            __cpuidex(registers, (int)0x8000000Au, 0);
            {
                const UINT64 end = AhdEndTsc();
                if (end >= begin && accepted < AHD_MAX_KERNEL_TIMING_SAMPLES) {
                    Report->SvmCpuidCycles[accepted] = end - begin;
                    ++accepted;
                } else {
                    ++Report->TimingRejectedCount;
                }
            }
        }
        Report->SvmTimingSampleCount = accepted;
    }

    accepted = 0;
    for (sample = 0; sample < Report->TimingSampleCount; ++sample) {
        const UINT64 begin = AhdBeginTsc();
        const UINT64 end = AhdEndTsc();
        if (end >= begin && accepted < AHD_MAX_KERNEL_TIMING_SAMPLES) {
            Report->BaselineCycles[accepted] = end - begin;
            ++accepted;
        } else {
            ++Report->TimingRejectedCount;
        }
    }
    if (accepted < Report->TimingSampleCount) {
        Report->TimingSampleCount = accepted;
    }
}

static NTSTATUS AhdCollectReport(
    _Out_ AHD_KERNEL_REPORT* Report,
    _In_ UINT32 RequestedTimingSamples)
{
    GROUP_AFFINITY requestedAffinity;
    GROUP_AFFINITY previousAffinity;
    PROCESSOR_NUMBER processor;
    UINT32 extendedMaximum;
    BOOLEAN affinitySet = FALSE;

    RtlZeroMemory(Report, sizeof(*Report));
    Report->Size = sizeof(*Report);
    Report->Version = AHD_PROTOCOL_VERSION;

    KeGetCurrentProcessorNumberEx(&processor);
    RtlZeroMemory(&requestedAffinity, sizeof(requestedAffinity));
    RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
    requestedAffinity.Group = processor.Group;
    requestedAffinity.Mask = ((KAFFINITY)1) << processor.Number;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        Report->OperationStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeSetSystemGroupAffinityThread(&requestedAffinity, &previousAffinity);
    affinitySet = TRUE;

    AhdReadCpuid(&Report->Cpuid[0], 0u, 0u);
    AhdReadCpuid(&Report->Cpuid[1], 1u, 0u);
    AhdReadCpuid(&Report->Cpuid[2], 0x80000000u, 0u);
    AhdReadCpuid(&Report->Cpuid[3], 0x80000001u, 0u);
    AhdReadCpuid(&Report->Cpuid[4], 0x8000000Au, 0u);
    AhdReadCpuid(&Report->Cpuid[5], 0x40000000u, 0u);

    if (!AhdIsAuthenticAmd(&Report->Cpuid[0])) {
        Report->OperationStatus = STATUS_NOT_SUPPORTED;
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        return STATUS_NOT_SUPPORTED;
    }

    Report->CpuFlags |= AHD_CPU_FLAG_AMD;
    if ((UINT32)Report->Cpuid[0].Eax >= 1u &&
        ((UINT32)Report->Cpuid[1].Ecx & (1u << 31)) != 0) {
        Report->CpuFlags |= AHD_CPU_FLAG_HYPERVISOR;
    }
    extendedMaximum = (UINT32)Report->Cpuid[2].Eax;
    if (extendedMaximum >= 0x80000001u) {
        if (((UINT32)Report->Cpuid[3].Ecx & (1u << 2)) != 0) {
            Report->CpuFlags |= AHD_CPU_FLAG_SVM;
        }
        if (((UINT32)Report->Cpuid[3].Edx & (1u << 27)) != 0) {
            Report->CpuFlags |= AHD_CPU_FLAG_RDTSCP;
        }
    }
    if ((Report->CpuFlags & AHD_CPU_FLAG_SVM) != 0 &&
        extendedMaximum >= 0x8000000Au && ((UINT32)Report->Cpuid[4].Edx & 1u) != 0) {
        Report->CpuFlags |= AHD_CPU_FLAG_NPT;
    }

    KeGetCurrentProcessorNumberEx(&processor);
    Report->ProcessorGroup = processor.Group;
    Report->ProcessorNumber = processor.Number;

    Report->Cr0 = __readcr0();
    Report->Cr3 = __readcr3();
    Report->Cr4 = __readcr4();

    Report->ProbeFlags = AHD_PROBE_FLAG_MAPPER_SAFE |
                         AHD_PROBE_FLAG_MSR_READS_SKIPPED |
                         AHD_PROBE_FLAG_RDTSC_TIMING;

    AhdCollectTiming(Report, RequestedTimingSamples);

    if ((Report->CpuFlags & AHD_CPU_FLAG_RDTSCP) != 0) {
        Report->ProbeFlags |= AHD_PROBE_FLAG_RDTSCP_TIMING |
                              AHD_PROBE_FLAG_STRESS_TIMING;
        AhdCollectConditionedTiming(Report, RequestedTimingSamples);
    }

    if (affinitySet) {
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        affinitySet = FALSE;
    }

    AhdCollectRepresentativeCores(Report);
    if (Report->CoreRecordCount != 0) {
        if ((Report->CpuFlags & AHD_CPU_FLAG_RDTSCP) != 0) {
            Report->ProbeFlags |= AHD_PROBE_FLAG_MULTICORE_TIMING;
        }
        if ((Report->CpuFlags & AHD_CPU_FLAG_SVM) != 0) {
            Report->ProbeFlags |= AHD_PROBE_FLAG_SVM_STABILITY;
        }
    }
    Report->OperationStatus = STATUS_SUCCESS;

    if (affinitySet) {
        KeRevertToUserGroupAffinityThread(&previousAffinity);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS AhdCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return AhdCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS AhdUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return AhdCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static NTSTATUS AhdDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    AHD_QUERY_REQUEST request;
    AHD_KERNEL_REPORT* report;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);
    stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack->Parameters.DeviceIoControl.IoControlCode != AHD_IOCTL_QUERY_REPORT) {
        return AhdCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(AHD_QUERY_REQUEST) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(AHD_KERNEL_REPORT) ||
        Irp->AssociatedIrp.SystemBuffer == NULL) {
        return AhdCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    RtlCopyMemory(&request, Irp->AssociatedIrp.SystemBuffer, sizeof(request));
    if (request.Size != sizeof(request) || request.Version != AHD_PROTOCOL_VERSION) {
        return AhdCompleteIrp(Irp, STATUS_REVISION_MISMATCH, 0);
    }
    if (request.Reserved != 0 || request.RequestedTimingSamples == 0 ||
        request.RequestedTimingSamples > AHD_MAX_KERNEL_TIMING_SAMPLES) {
        return AhdCompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    report = (AHD_KERNEL_REPORT*)Irp->AssociatedIrp.SystemBuffer;
    status = KeWaitForSingleObject(
        &AhdProbeMutex,
        Executive,
        KernelMode,
        FALSE,
        NULL);
    if (!NT_SUCCESS(status)) {
        return AhdCompleteIrp(Irp, status, 0);
    }
    status = AhdCollectReport(report, request.RequestedTimingSamples);
    KeReleaseMutex(&AhdProbeMutex, FALSE);
    return AhdCompleteIrp(
        Irp,
        status,
        NT_SUCCESS(status) ? sizeof(AHD_KERNEL_REPORT) : 0);
}

static NTSTATUS AhdInitialize(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    UNICODE_STRING securityDescriptor;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;
    ULONG index;

    UNREFERENCED_PARAMETER(RegistryPath);
#pragma warning(push)
#pragma warning(disable: 28168 28169) // One rejecting fallback intentionally fills every unsupported slot.
    for (index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index) {
        DriverObject->MajorFunction[index] = AhdUnsupported;
    }
#pragma warning(pop)
    DriverObject->MajorFunction[IRP_MJ_CREATE] = AhdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = AhdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AhdCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AhdDeviceControl;
    // A kdmapper image has no loader-backed lifetime. Reboot is the only
    // supported cleanup path; publishing an unload callback would be unsafe.
    DriverObject->DriverUnload = NULL;

    KeInitializeMutex(&AhdProbeMutex, 0);

    RtlInitUnicodeString(&deviceName, AHD_DEVICE_NT_NAME);
    RtlInitUnicodeString(&symbolicLink, AHD_DEVICE_DOS_NAME);
    RtlInitUnicodeString(&securityDescriptor, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &securityDescriptor,
        &AHD_DEVICE_CLASS_GUID,
        &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING routineName;
    UNICODE_STRING driverName;
    AHD_IO_CREATE_DRIVER ioCreateDriver;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    // kdmapper entry arguments are not assumed to be a valid DRIVER_OBJECT or
    // registry path. IoCreateDriver creates the object and invokes AhdInitialize.
    RtlInitUnicodeString(&routineName, L"IoCreateDriver");
    ioCreateDriver = (AHD_IO_CREATE_DRIVER)MmGetSystemRoutineAddress(&routineName);
    if (ioCreateDriver == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    RtlInitUnicodeString(&driverName, L"\\Driver\\AmdHvDetector");
    return ioCreateDriver(&driverName, AhdInitialize);
}
