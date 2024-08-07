// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package preinstall

import (
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	internal_efi "github.com/snapcore/secboot/internal/efi"
)

const (
	pcClientClass uint32 = 0x00000001
)

var (
	// ErrNoTPM2Device is returned wrapped from RunChecks if there is no
	// TPM2 device.
	ErrNoTPM2Device = internal_efi.ErrNoTPM2Device

	// ErrTPMLockout is returned wrapped from RunChecks if the TPM is in DA
	// lockout mode. If the existing lockout hierarchy authorization value is not
	// known then the TPM will most likely need to be cleared.
	ErrTPMLockout = errors.New("TPM is in DA lockout mode")

	// ErrTPMAlreadyOwned is returned wrapped from RunChecks if the authorization
	// value for the owner or endorsement hierarchies are set (which currently isn't
	// supported by snapd), or the lockout hierarchy is already set but the
	// PostInstallChecks flag isn't supplied. If the lockout hierarchy is set at
	// pre-install time, then the TPM will most likely need to be cleared.
	ErrTPMAlreadyOwned = errors.New("TPM is already owned")

	// ErrInsufficientNVCounters is returned wrapped from RunChecks if there are
	// insufficient NV counters available for PCR policy revocation. If this is still
	// the case after a TPM clear then it means that the platform firmware is using
	// most of the allocation of available counters for itself, and maybe the
	// feature needs to be disabled by snapd.
	ErrInsufficientNVCounters = errors.New("insufficient NV counters available")

	// ErrNoPCClientTPM is returned wrapped from RunChecks if a TPM2 device exists
	// but it doesn't claim to be meet the requirements for PC-Client. Note that swtpm
	// used by VM's don't behave correctly here, so we account for that instead of
	// returning an error.
	ErrNoPCClientTPM = errors.New("TPM2 device is present but it is not a PC-Client TPM")

	// ErrTPMDisabled is returned wrapped from RunChecks if a TPM2 device exists but
	// it is currently disabled. It can be reenabled by the firmware by making use of the
	// [github.com/canonical/go-tpm2/ppi.PPI] interface, obtained by using
	// [github.com/canonical/go-tpm2/linux/RawDevice.PhysicalPresenceInterface].
	ErrTPMDisabled = errors.New("TPM2 device is present but is currently disabled by the platform firmware")
)

type checkTPM2DeviceFlags int

const (
	checkTPM2DeviceInVM checkTPM2DeviceFlags = 1 << iota
	checkTPM2DevicePostInstall
)

// openAndCheckTPM2Device opens the default TPM device for the associated environment and
// performs some checks on it. It returns an open TPMContext and whether the TPM is a discrete
// TPM if these checks are successful.
func openAndCheckTPM2Device(env internal_efi.HostEnvironment, flags checkTPM2DeviceFlags) (tpm *tpm2.TPMContext, discreteTPM bool, err error) {
	// Get a device from the supplied environment
	device, err := env.TPMDevice()
	if err != nil {
		return nil, false, err
	}

	// Open it!
	tpm, err = tpm2.OpenTPMDevice(device)
	if err != nil {
		return nil, false, fmt.Errorf("cannot open TPM device: %w", err)
	}
	savedTpm := tpm
	defer func() {
		// Make sure it gets closed again if we return an error
		if err == nil {
			return
		}
		savedTpm.Close()
	}()

	// Make sure that the TPM is enabled. The firmware disables the TPM by disabling the
	// storage and endorsement hierarchies. Of course, user-space can do this as well, although
	// it requires a TPM reset to restore them anyway.
	sc, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyStartupClear)
	if err != nil {
		return nil, false, fmt.Errorf("cannot obtain value for TPM_PT_STARTUP_CLEAR: %w", err)
	}
	const enabledMask = tpm2.AttrShEnable | tpm2.AttrEhEnable
	if tpm2.StartupClearAttributes(sc)&enabledMask != enabledMask {
		return nil, false, ErrTPMDisabled
	}

	perm, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyPermanent)
	if err != nil {
		return nil, false, fmt.Errorf("cannot obtain value for TPM_PT_PERMANENT: %w", err)
	}

	// Make sure that the DA lockout mode is not activated.
	if tpm2.PermanentAttributes(perm)&tpm2.AttrInLockout > 0 {
		return nil, false, ErrTPMLockout
	}

	// Make sure the lockout hierarchy auth value hasn't been set, unless we are
	// being called in post-install mode.
	if flags&checkTPM2DevicePostInstall == 0 {
		if tpm2.PermanentAttributes(perm)&tpm2.AttrLockoutAuthSet > 0 {
			return nil, false, ErrTPMAlreadyOwned
		}
	}
	// Make sure the owner and endorsement hierarchy authorization values have never been set.
	// We don't support this yet - this needs to be coordinated with snapd because snapd will need
	// access to these values.
	if tpm2.PermanentAttributes(perm)&(tpm2.AttrOwnerAuthSet|tpm2.AttrEndorsementAuthSet) > 0 {
		// We don't support setting these at all yet
		return nil, false, ErrTPMAlreadyOwned
	}

	// Check TPM2 device class. The class is associated with a TPM Profile (PTP) spec
	// which says a lot about the TPM such as mandatory commands, algorithms, PCR banks
	// and the minimum number of PCRs. In all honesty, we're only ever likely to see
	// PC-Client devices here because that's basically all that exists, but check anyway
	// just in case.
	psFamily, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyPSFamilyIndicator)
	if err != nil {
		return nil, false, fmt.Errorf("cannot obtain value for TPM_PT_PS_FAMILY_INDICATOR: %w", err)
	}
	if psFamily != pcClientClass {
		// swtpm sets TPM_PT_PS_FAMILY_INDICATOR to the same value as TPM_PT_FAMILY_INDICATOR,
		// which is incorrect - the latter is "2.0" in ASCII with a NULL terminator and is used
		// to indicate the major version of the TCG reference library supported by the TPM. The
		// former indicates the class, as described earlier, and is 0 in the reference
		// implementation and should be 1 for PC-Client. Permit this bug if we are running in a VM.
		if flags&checkTPM2DeviceInVM == 0 {
			// We're not in a VM, so expect the proper PC-Client value.
			return nil, false, ErrNoPCClientTPM
		}
		// In a VM, make sure that the value of TPM_PT_PS_FAMILY_INDICATOR == TPM_PT_FAMILY_INDICATOR.
		// I think that this is always the case, but we might need to add additional VM-specific quirks here.
		family, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyFamilyIndicator)
		if err != nil {
			return nil, false, fmt.Errorf("cannot obtain value for TPM_PT_FAMILY_INDICATOR: %w", err)
		}
		if family != psFamily {
			// This doesn't have the swtpm quirk, so we have no idea what sort of vTPM we have
			// at this point - just return an error because we aren't going to check for every
			// individual TPM feature.
			return nil, false, ErrNoPCClientTPM
		}
	}

	// Make sure we have enough NV counters for PCR policy revocation. We need at least 2 (1 normally, and
	// an extra 1 during reprovision). The platform firmware may use up some of the allocation.
	nvCountersMax, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyNVCountersMax)
	if err != nil {
		return nil, false, fmt.Errorf("cannot obtain value for TPM_NV_COUNTERS_MAX: %w", err)
	}
	if nvCountersMax > 0 {
		// If the TPM returns 0, there are no limits to the number of counters other than
		// available NV storage. Obtain the number of active counters.
		nvCounters, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyNVCounters)
		if err != nil {
			return nil, false, fmt.Errorf("cannot obtain value for TPM_NV_COUNTERS_MAX: %w", err)
		}
		required := uint32(1) // extra index for re-provision
		if flags&checkTPM2DevicePostInstall == 0 {
			// This is pre-install, so we need the initial index for provision
			required += 1
		}
		if (nvCountersMax - nvCounters) < required {
			return nil, false, ErrInsufficientNVCounters
		}
	}

	// Determine whether we have a discrete TPM by querying the manufacturer.
	// Assume that Intel is firmware (ie, Intel PTT) and everything else is discrete
	// unless we are in a VM.
	// TODO: Investigate whether this is the best way to detect a discrete TPM.
	//  There may be more than Intel PTT in the firmware world, eg, AMD might have
	//  its own and ARM devices with UEFI firmware implementations may have
	//  firmware based TPMs running in a TEE. I suspect this is not the best way to
	//  do this but is ok for an initial implementation.
	manufacturer, err := tpm.GetManufacturer()
	if err != nil {
		return nil, false, fmt.Errorf("cannot obtain value for TPM_PT_MANUFACTURER: %w", err)
	}

	discreteTPM = manufacturer != tpm2.TPMManufacturerINTC
	if flags&checkTPM2DeviceInVM > 0 {
		discreteTPM = false
	}
	return tpm, discreteTPM, nil
}
