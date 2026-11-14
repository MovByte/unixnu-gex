//! The pipe's runtime properties, as AppleMobileDispH9G keeps them and
//! publishes them on the framebuffer.
//!
//! - Each has an id (`RuntimeProperty`), a name (IOMobileGraphicsFamily's
//!   `IOMFB::getRuntimePropertyName`, 0xfffffff00677d36c, for the idle
//!   detectors 0xe9 to 0xf4 and the gamut conversion locations 0xe6 to
//!   0xe8; 0xfffffff00677c05c for the rest) and a type (0xfffffff00677b900:
//!   0 a boolean, 1 and 2 numbers).
//! - The pipe registers a property in its table (`FUN_fffffff006bde66c`,
//!   reached from every registration site in the kext; [`REGISTERED`]),
//!   and registering publishes it: the property's publish call
//!   (0xfffffff006bb30e8) has the table's publisher (0xfffffff006bea4e4)
//!   set the framebuffer's registry property of that name, an OSBoolean
//!   for a boolean and a 32-bit OSNumber for a number. Setting its value
//!   (0xfffffff006bde7c4) publishes it again.
//! - A name of a property the pipe never registers is no property of the
//!   framebuffer, unless other code sets that name: four names are formed
//!   elsewhere in the kernelcache besides the name tables, and are not
//!   answered here ([`ELSEWHERE`]).
//! - A registered property's starting value is the registration's, which
//!   [`START`] has for those worked out; the rest are reported when read.

use super::super::iokit::Prop;

/// The runtime properties' names, by id.
const NAMES: [(u8, &str); 245] = [
    (0x00, "BlendOutputCSCMethod"),
    (0x01, "CMDegammaMethod"),
    (0x02, "DisplayWallFBs"),
    (0x03, "DisplayWallConfig"),
    (0x04, "DisplayWallTiming"),
    (0x05, "IOMFBSupportsHeadOfLineSwaps"),
    (0x06, "requestPixelBacklightModulation"),
    (0x07, "forcePixelBacklightModulation"),
    (0x08, "overrideLPFControls"),
    (0x09, "LPFControlValue"),
    (0x0a, "LPFControl2Value"),
    (0x0b, "overrideDPBMaxSlopes"),
    (0x0c, "DPBLPFMaxSlopeValue"),
    (0x0d, "DPBMaxSlopeValue"),
    (0x0e, "overrideBacklight"),
    (0x0f, "backlightValue"),
    (0x10, "enableGammaCorrection"),
    (0x11, "brightnessCorrection"),
    (0x12, "brightnessCorrectionB"),
    (0x13, "IOMFBBrightnessLevel"),
    (0x14, "IOMFBIndicatorBrightnessNits"),
    (0x15, "IOMFBSecureContentFactor"),
    (0x16, "IOMFBSecureIndicatorFactor"),
    (0x17, "IOMFBBrightnessLevelMA"),
    (0x18, "IOMFBBrightnessLevelIDAC"),
    (0x19, "IOMFBContrastEnhancerStrength"),
    (0x1a, "IOMFBBrightnessCompensationEnable"),
    (0x1b, "IOMFBTemperatureCompensationEnable"),
    (0x1c, "enableDither"),
    (0x1d, "enableDarkEnhancer"),
    (0x1e, "enableADBEColorManager"),
    (0x1f, "enableWhitePointCorrection"),
    (0x20, "enable2DTemperatureCorrection"),
    (0x21, "enable2DTemperatureCorrection"),
    (0x22, "enableDefaultTemperatureCorrection"),
    (0x23, "defaultTemperatureCorrectionValue"),
    (0x24, "use0DSensorFor2DTemp"),
    (0x25, "TemperatureStructVersion2D"),
    (0x26, "IOMFBDigitalDimmingLevel"),
    (0x27, "set0DTempSensorValue"),
    (0x28, "uniformity2D"),
    (0x29, "enableAmbientLightSensorStatistics"),
    (0x2a, "enableSubPixelLayoutCompensation"),
    (0x2b, "enablePartialUpdate"),
    (0x2c, "enableLatLeakComp"),
    (0x2d, "enableHighGrayOD"),
    (0x2e, "AmbientBrightness"),
    (0x2f, "enableGamutMapper"),
    (0x30, "enableStats"),
    (0x31, "maxAverageBpp"),
    (0x32, "maxPeakBpp"),
    (0x33, "clockRatio"),
    (0x34, "DebugUInt32"),
    (0x35, "VRRDivisor"),
    (0x36, "VRRVersion"),
    (0x37, "darkBoot"),
    (0x38, "IOMFBWideGamutPassthrough"),
    (0x39, "enableFiltersNoRewriteMode"),
    (0x3a, "enablePLCMode"),
    (0x3b, "enableABGMode"),
    (0x3c, "enableABGDynamicMap"),
    (0x3d, "disableDBSR"),
    (0x3e, "enableDBMMode"),
    (0x3f, "enableBICMode"),
    (0x40, "enableBICUpdates"),
    (0x41, "enableSBIM"),
    (0x42, "enableGPDeringing"),
    (0x43, "enableGPAlphaDiv"),
    (0x44, "twilightStrength"),
    (0x45, "ammoliteStrength"),
    (0x46, "ccParamsVersion"),
    (0x47, "ApriTempOverride"),
    (0x48, "ApriBrightOverride"),
    (0x49, "EnableApri"),
    (0x4a, "allocateDefaultFramebuffer"),
    (0x4b, "debugHardPowerEvent"),
    (0x4c, "ESDThresholdMS"),
    (0x4d, "EnableKernelTests"),
    (0x4e, "DisableDisplayOptimize"),
    (0x4f, "QMSVRREnableConfig"),
    (0x50, "EnableEven60FPSFrames"),
    (0x51, "PanicOnHungSwap"),
    (0x52, "FakeTconESDEvent"),
    (0x53, "RuntimeProperty::registerTraceEnable"),
    (0x54, "RuntimeProperty::frameInfoTraceEnable"),
    (0x55, "QoSDebug"),
    (0x56, "enablePowerGateDCS"),
    (0x57, "enableVideoCaching"),
    (0x58, "dummySystemWantsCaching"),
    (0x59, "disableSystemCachingInput"),
    (0x5a, "enableMockALSSCapture"),
    (0x5b, "APTFixedRR"),
    (0x5c, "AODFixedRR"),
    (0x5d, "AODWaitForWalkdown"),
    (0x5e, "PCCEnableLogs"),
    (0x5f, "APTEnableLogs"),
    (0x60, "APTEnableCDFD"),
    (0x61, "APTEnablePRC"),
    (0x62, "APTEnableConfigExpired"),
    (0x63, "APTEnableCA"),
    (0x64, "BLNitsCap"),
    (0x65, "RTPLCBLNitsCap"),
    (0x66, "RTPLCBLNitsScaler"),
    (0x67, "RTPLCNitsThresh"),
    (0x68, "APTEnableEvents"),
    (0x69, "APTEventsMask"),
    (0x6a, "NormalModeEnable"),
    (0x6b, "APTEnableDefaultGray"),
    (0x6c, "APTDefaultGrayValue"),
    (0x6d, "IOMFBStatsTapPoint"),
    (0x6e, "FrameInfoForRepeats"),
    (0x6f, "APTResetCA"),
    (0x70, "ChargeValuesPublish"),
    (0x71, "ChargeValuesReset"),
    (0x72, "APTPanicOnChargeOOB"),
    (0x73, "APTPanicOnChargeParity"),
    (0x74, "APTPanicOnStuckPolarity"),
    (0x75, "APTLimitRefreshRate"),
    (0x76, "SkipRegion"),
    (0x77, "ExportCRCAtVBI"),
    (0x78, "IdleCachingMethod"),
    (0x79, "PCCCabalEnable"),
    (0x7a, "PCCStabilityThreshold"),
    (0x7b, "PCCStabilityThresholdAOT"),
    (0x7c, "IOMFBSupportsICC"),
    (0x7d, "IOMFBSupports2DBL"),
    (0x7e, "IOMFBSupportsGPLite"),
    (0x7f, "IOMFBIntDcpUsedForExtWhenLidClose"),
    (0x80, "IOMFBSupportsHDR10Plus"),
    (0x81, "PCCTrinityEnable"),
    (0x82, "PCC0DBLCTrinityEnable"),
    (0x83, "PCCEnable"),
    (0x84, "PCC0DBLCEnable"),
    (0x85, "PCC2DEnable"),
    (0x86, "BypassPCC2DLed"),
    (0x87, "PCC2DLedAccelOut"),
    (0x88, "PCC2DLedAccelLog"),
    (0x89, "DisablePCC2DBrc"),
    (0x8a, "DisableTempComp"),
    (0x8b, "IOMFBDoPODBoost"),
    (0x8c, "IOMFBPODBoost"),
    (0x8d, "UIVibrancyBoost"),
    (0x8e, "UIVibrancyEnable"),
    (0x8f, "ModeBlm"),
    (0x90, "IOMFBTestBacklightDimValue"),
    (0x91, "BLMVLEDManual"),
    (0x92, "BLMAHOutputFreq"),
    (0x93, "BLMAHMode"),
    (0x94, "BLMPLimitCfg"),
    (0x95, "enableBLMSloper"),
    (0x96, "enableLAC"),
    (0x97, "BLMAHUPCount"),
    (0x98, "M3DiagsTimeout"),
    (0x99, "DisableBConBoot"),
    (0x9a, "BLMPowergateEnable"),
    (0x9b, "IOMFBAllowAnnouncingPTS"),
    (0x9c, "enableLinearToPanel"),
    (0x9d, "APTPDCEnable"),
    (0x9e, "APTPDCEnablePM"),
    (0x9f, "APTPDCEnableRepeat"),
    (0xa0, "PDCGlobalTemp"),
    (0xa1, "PDCSettleCount"),
    (0xa2, "PDCSaveLongFrames"),
    (0xa3, "PDCSaveRepeatUnstablePCC"),
    (0xa4, "PDCEntryTime"),
    (0xa5, "PDCExitTime"),
    (0xa6, "PDCAlwaysOnNits"),
    (0xa7, "PDCContentSwitchCount"),
    (0xa8, "pccLumaGammaFactor"),
    (0xa9, "PDCCutoffLux"),
    (0xaa, "PDCExitCount"),
    (0xab, "overdriveCompCutoff"),
    (0xac, "hgodCutoff"),
    (0xad, "AOTEnable"),
    (0xae, "VSHHistVal"),
    (0xaf, "CECorrectionFactor"),
    (0xb0, "ProxScanPlan"),
    (0xb1, "ProxScanPosition"),
    (0xb2, "SWSTemp"),
    (0xb3, "ForceAOTARMode"),
    (0xb4, "EmissionFrequency"),
    (0xb5, "SupportsAOTPowerSaving"),
    (0xb6, "SPUCEnable"),
    (0xb7, "QETCEnable"),
    (0xb8, "TLSCEnable"),
    (0xb9, "USPUCEnable"),
    (0xba, "ClearUSPUCData"),
    (0xbb, "USPUCDefaultData"),
    (0xbc, "BLMAHOutputLogEnable"),
    (0xbd, "BLMAHStatsLogEnable"),
    (0xbe, "BLMStandbyEnable"),
    (0xbf, "VUCEnable"),
    (0xc0, "IRDCEnable"),
    (0xc1, "IRDCFrameReset"),
    (0xc2, "IRDCFrameMaxResetCount"),
    (0xc3, "IRDCFrameMinResetCount"),
    (0xc4, "limit_max_physical_brightness"),
    (0xc5, "PTUCEnable"),
    (0xc6, "PTUCOverrideTemp"),
    (0xc7, "RTPLCEnable"),
    (0xc8, "RTPLCEnableRT"),
    (0xc9, "RTPLCEnableFD"),
    (0xca, "RTPLCEnableNitsCap"),
    (0xcb, "RTPLCEnablePredThreshCross"),
    (0xcc, "RTPLCEnableFixedKnee"),
    (0xcd, "RTPLCEnableFDBicMult"),
    (0xce, "usePodBoostAtRTPLCFDLUT"),
    (0xcf, "RTPLCEnableFDPixelModAfterRTTrig"),
    (0xd0, "RTPLCRecoveryCoeff"),
    (0xd1, "enableSWS"),
    (0xd2, "enablePixelCapture"),
    (0xd3, "PixelCaptureConfig"),
    (0xd4, "PixelCaptureBlockMask"),
    (0xd5, "GP0PixelCaptureLocation"),
    (0xd6, "GP1PixelCaptureLocation"),
    (0xd7, "IOMFBApplyBrightnessProps"),
    (0xd8, "BlendPixelCaptureLocation"),
    (0xd9, "CMPixelCaptureLocation"),
    (0xda, "PCCBLCPixelCaptureLocation"),
    (0xdb, "WPCPixelCaptureLocation"),
    (0xdc, "BICSPixelCaptureLocation"),
    (0xdd, "RTPLCPixelCaptureLocation"),
    (0xde, "CalCLutPixelCaptureLocation"),
    (0xdf, "CCPixelCaptureLocation"),
    (0xe0, "GPLiteMaxSrcSz"),
    (0xe1, "enableDisplayTMDpc"),
    (0xe2, "LTHSaveDispPerfBoostEnable"),
    (0xe3, "ADCLLoadAll"),
    (0xe4, "forceEnableACSS"),
    (0xe5, "ForceSecureAnimation"),
    (0xe6, "gamutConversionPipe0"),
    (0xe7, "gamutConversionPipe1"),
    (0xe8, "gamutConversionPostBlend"),
    (0xe9, "SystemIdlenessEnabled"),
    (0xea, "SystemIdlenessThreshold"),
    (0xeb, "VRRIdleEnabled"),
    (0xec, "VRRIdleThreshold"),
    (0xed, "VRRBurnInEnabled"),
    (0xee, "VRRBurnInThreshold"),
    (0xef, "VRRBurnInCooldownEnabled"),
    (0xf0, "VRRBurnInCooldownThreshold"),
    (0xf1, "PowerGateADPIdleEnabled"),
    (0xf2, "PowerGateADPIdleThreshold"),
    (0xf3, "DisplayWallIdleEnabled"),
    (0xf4, "DisplayWallIdleThreshold"),
];
/// The ids the pipe registers (every registration site, whether or not it
/// runs at a given start), with their types.
const REGISTERED: [(u8, u8); 84] = [
    (0x00, 1), // BlendOutputCSCMethod
    (0x06, 0), // requestPixelBacklightModulation
    (0x07, 1), // forcePixelBacklightModulation
    (0x08, 0), // overrideLPFControls
    (0x09, 1), // LPFControlValue
    (0x0a, 1), // LPFControl2Value
    (0x0b, 0), // overrideDPBMaxSlopes
    (0x0c, 1), // DPBLPFMaxSlopeValue
    (0x0d, 1), // DPBMaxSlopeValue
    (0x0e, 0), // overrideBacklight
    (0x0f, 1), // backlightValue
    (0x11, 2), // brightnessCorrection
    (0x13, 2), // IOMFBBrightnessLevel
    (0x14, 2), // IOMFBIndicatorBrightnessNits
    (0x15, 2), // IOMFBSecureContentFactor
    (0x16, 2), // IOMFBSecureIndicatorFactor
    (0x19, 2), // IOMFBContrastEnhancerStrength
    (0x1a, 0), // IOMFBBrightnessCompensationEnable
    (0x1b, 0), // IOMFBTemperatureCompensationEnable
    (0x1c, 0), // enableDither
    (0x1d, 0), // enableDarkEnhancer
    (0x20, 0), // enable2DTemperatureCorrection
    (0x21, 0), // enable2DTemperatureCorrection
    (0x22, 0), // enableDefaultTemperatureCorrection
    (0x23, 2), // defaultTemperatureCorrectionValue
    (0x24, 0), // use0DSensorFor2DTemp
    (0x25, 1), // TemperatureStructVersion2D
    (0x27, 2), // set0DTempSensorValue
    (0x28, 0), // uniformity2D
    (0x2c, 0), // enableLatLeakComp
    (0x2d, 0), // enableHighGrayOD
    (0x2e, 2), // AmbientBrightness
    (0x2f, 0), // enableGamutMapper
    (0x31, 2), // maxAverageBpp
    (0x32, 2), // maxPeakBpp
    (0x33, 2), // clockRatio
    (0x34, 1), // DebugUInt32
    (0x37, 0), // darkBoot
    (0x3a, 0), // enablePLCMode
    (0x44, 2), // twilightStrength
    (0x47, 2), // ApriTempOverride
    (0x48, 2), // ApriBrightOverride
    (0x49, 0), // EnableApri
    (0x4e, 1), // DisableDisplayOptimize
    (0x4f, 1), // QMSVRREnableConfig
    (0x53, 0), // RuntimeProperty::registerTraceEnable
    (0x54, 0), // RuntimeProperty::frameInfoTraceEnable
    (0x55, 1), // QoSDebug
    (0x5b, 1), // APTFixedRR
    (0x5c, 1), // AODFixedRR
    (0x5d, 1), // AODWaitForWalkdown
    (0x5e, 0), // PCCEnableLogs
    (0x5f, 0), // APTEnableLogs
    (0x60, 0), // APTEnableCDFD
    (0x61, 0), // APTEnablePRC
    (0x62, 0), // APTEnableConfigExpired
    (0x63, 0), // APTEnableCA
    (0x68, 0), // APTEnableEvents
    (0x69, 1), // APTEventsMask
    (0x6a, 0), // NormalModeEnable
    (0x6b, 0), // APTEnableDefaultGray
    (0x6c, 1), // APTDefaultGrayValue
    (0x6d, 1), // IOMFBStatsTapPoint
    (0x6e, 0), // FrameInfoForRepeats
    (0x6f, 0), // APTResetCA
    (0x70, 0), // ChargeValuesPublish
    (0x71, 0), // ChargeValuesReset
    (0x72, 0), // APTPanicOnChargeOOB
    (0x73, 0), // APTPanicOnChargeParity
    (0x74, 0), // APTPanicOnStuckPolarity
    (0x75, 0), // APTLimitRefreshRate
    (0x9d, 0), // APTPDCEnable
    (0x9e, 1), // APTPDCEnablePM
    (0xa1, 1), // PDCSettleCount
    (0xa2, 0), // PDCSaveLongFrames
    (0xa3, 0), // PDCSaveRepeatUnstablePCC
    (0xac, 2), // hgodCutoff
    (0xad, 0), // AOTEnable
    (0xb0, 1), // ProxScanPlan
    (0xb1, 1), // ProxScanPosition
    (0xb5, 0), // SupportsAOTPowerSaving
    (0xe1, 0), // enableDisplayTMDpc
    (0xe3, 0), // ADCLLoadAll
    (0xe5, 0), // ForceSecureAnimation
];

/// The ids whose names other code forms besides IOMobileGraphicsFamily's
/// name tables: IOMFBSupportsHeadOfLineSwaps (AppleMobileDispH9G
/// 0xfffffff006c04fb0, 0xfffffff006c05568), EnableKernelTests (a pointer
/// at 0xfffffff006e663d8), IdleCachingMethod (0xfffffff006bf649c) and
/// IOMFBTestBacklightDimValue (0xfffffff006be4110, 0xfffffff006be4144).
const ELSEWHERE: [u8; 4] = [0x05, 0x4d, 0x78, 0x90];

/// The starting values worked out, by id:
/// - 0x00 `BlendOutputCSCMethod`: 0, which the blend output CSC block
///   (the pipe's +0x1c78, made by its init 0xfffffff006bb540c) registers
///   (0xfffffff006bb1914).
/// - 0xad `AOTEnable`: false, which the block manager's setup
///   (0xfffffff006bd0b2c) registers in the pipe's table (`+0x1b80`) and
///   the display's power evaluation reads (0xfffffff006bd26c8).
/// - 0xb5 `SupportsAOTPowerSaving`: the pipe's virtual at +0x650
///   (0xfffffff006bbd2c0, false), which the block manager's setup
///   registers (`FUN_fffffff006bd0b2c`).
///
/// - The block manager's setup (0xfffffff006bd0b2c) registers in the pipe's
///   table with constants, or with what this boot gives: no boot-arg it
///   reads is set (each `iomfb_*` read fails), the pipe's slots +0x498,
///   +0x4f0, +0x4f8 and +0x368 answer 0 and +0x358 answers 1, and of its
///   components (+0xd0 to +0x108) the 2D temperature correction (+0xe8),
///   the temperature compensation (+0x100) and the brightness compensation
///   (+0x108) are made. So: 0x21 `enable2DTemperatureCorrection` and 0x22
///   `enableDefaultTemperatureCorrection` false whatever 0x20 is; 0x24
///   `use0DSensorFor2DTemp` false (slot +0x4f8); 0x25
///   `TemperatureStructVersion2D` 1 (slot +0x358); 0x28 `uniformity2D`
///   false (no +0xd8 component); 0xe3 `ADCLLoadAll` true; the APT switches
///   0x60 false, 0x61 and 0x63 true (no boot-arg), 0x62 true (slot +0x498
///   false, negated), 0x6f false, 0x68 false, 0x69 0, 0x5e and 0x5f false,
///   0x6b true, 0x6c 0xff; 0x9d true; 0x9e and 0xa1 1; 0xa2 and 0xa3 false;
///   0xe5 false; 0x5b and 0x5c 0 and 0x5d 1 (no boot-arg); 0x70 to 0x75 and
///   0x6e false; 0xb0 0xffffffff and 0xb1 0.
///
/// At start nothing else sets these: a boolean or 32-bit runtime property
/// changes through the framebuffer's slot at +0x9e8 (0xfffffff006bf4568,
/// the only caller of the setter 0xfffffff006bea2dc), which only the
/// `iomfb_RuntimeProperty_*` boot-args (none on this boot) and
/// `AppleCLCD::setProperties` reach. The 64-bit ones have other setters
/// (0xfffffff006bea1f8's callers), and are left out until those are worked
/// out.
const START: [(u8, u32); 38] = [
    (0x00, 0),
    (0x21, 0),
    (0x22, 0),
    (0x24, 0),
    (0x25, 1),
    (0x28, 0),
    (0x5b, 0),
    (0x5c, 0),
    (0x5d, 1),
    (0x5e, 0),
    (0x5f, 0),
    (0x60, 0),
    (0x61, 1),
    (0x62, 1),
    (0x63, 1),
    (0x68, 0),
    (0x69, 0),
    (0x6b, 1),
    (0x6c, 0xff),
    (0x6e, 0),
    (0x6f, 0),
    (0x70, 0),
    (0x71, 0),
    (0x72, 0),
    (0x73, 0),
    (0x74, 0),
    (0x75, 0),
    (0x9d, 1),
    (0x9e, 1),
    (0xa1, 1),
    (0xa2, 0),
    (0xa3, 0),
    (0xad, 0),
    (0xb0, 0xffff_ffff),
    (0xb1, 0),
    (0xb5, 0),
    (0xe3, 1),
    (0xe5, 0),
];

/// The registered ids whose only registration needs a component of the
/// pipe that this kernelcache never makes (its `+0xd0`, `+0xe0` and `+0xf0`
/// are only ever cleared): 0x2c `enableLatLeakComp` (with `+0xe0`), 0x2f
/// `enableGamutMapper` (with `+0xd0`), and 0x2d `enableHighGrayOD` and 0xac
/// `hgodCutoff` (with `+0xf0`), all in 0xfffffff006bd0b2c. They are never
/// published, and read are answered missing.
const NOT_MADE: [u8; 4] = [0x2c, 0x2d, 0x2f, 0xac];

/// The id of the runtime property `name`.
pub fn id_of(name: &str) -> Option<u8> {
    NAMES.iter().find(|(_, n)| *n == name).map(|&(id, _)| id)
}

/// The type (0 a boolean, 1 or 2 a number) of the registered property `id`.
fn registered(id: u8) -> Option<u8> {
    REGISTERED.iter().find(|(i, _)| *i == id).map(|&(_, t)| t)
}

/// Whether `name` is a runtime property's name that the framebuffer has no
/// property of.
pub fn absent(name: &str) -> bool {
    id_of(name).is_some_and(|id| (registered(id).is_none() || NOT_MADE.contains(&id)) && !ELSEWHERE.contains(&id))
}

/// The value of registered property `id` now, if worked out.
pub fn value(id: u8) -> Option<u32> {
    START.iter().find(|(i, _)| *i == id).map(|&(_, v)| v)
}

/// The framebuffer's registry property `name` when it is a published
/// runtime property whose value is worked out.
pub fn published(name: &str) -> Option<Prop> {
    let id = id_of(name)?;
    let ty = registered(id)?;
    let v = value(id)?;
    Some(if ty == 0 { Prop::Bool(v != 0) } else { Prop::Num(u64::from(v), 32) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_names_and_what_is_published() {
        // The idle detectors' and gamut locations' names, by their index.
        assert_eq!(id_of("VRRIdleEnabled"), Some(0xeb));
        assert_eq!(id_of("DisplayWallIdleThreshold"), Some(0xf4));
        assert_eq!(id_of("gamutConversionPostBlend"), Some(0xe8));
        assert_eq!(id_of("IOMFBSupportsGPLite"), Some(0x7e));
        // Never registered: no property.
        assert!(absent("IOMFBSupportsGPLite") && absent("VRRIdleEnabled") && absent("IOMFBIntDcpUsedForExtWhenLidClose"));
        // Registered, or formed elsewhere too: not answered missing.
        assert!(!absent("SupportsAOTPowerSaving") && !absent("IdleCachingMethod") && !absent("TimingElements"));
        // Published with their starting values; unworked ones are not.
        assert_eq!(published("SupportsAOTPowerSaving"), Some(Prop::Bool(false)));
        assert_eq!(published("BlendOutputCSCMethod"), Some(Prop::Num(0, 32)));
        assert_eq!(published("ADCLLoadAll"), Some(Prop::Bool(true)));
        assert_eq!(published("ProxScanPlan"), Some(Prop::Num(0xffff_ffff, 32)));
        assert_eq!(published("APTDefaultGrayValue"), Some(Prop::Num(0xff, 32)));
        assert_eq!(published("QoSDebug"), None);
        // Registered only with a component the pipe never makes: missing.
        assert!(absent("enableGamutMapper") && absent("hgodCutoff") && absent("enableLatLeakComp") && absent("enableHighGrayOD"));
        assert_eq!(published("enableGamutMapper"), None);
        assert_eq!(published("VRRIdleEnabled"), None);
    }
}
