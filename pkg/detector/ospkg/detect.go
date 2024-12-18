package ospkg

import (
	"time"

	"github.com/zhanglimao/trivy/pkg/detector/ospkg/alma"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/alpine"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/amazon"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/chainguard"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/debian"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/mariner"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/oracle"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/photon"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/redhat"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/rocky"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/suse"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/ubuntu"
	"github.com/zhanglimao/trivy/pkg/detector/ospkg/wolfi"
	fos "github.com/zhanglimao/trivy/pkg/fanal/analyzer/os"
	ftypes "github.com/zhanglimao/trivy/pkg/fanal/types"
	"github.com/zhanglimao/trivy/pkg/log"
	"github.com/zhanglimao/trivy/pkg/types"
	"golang.org/x/xerrors"
)

var (
	// ErrUnsupportedOS defines error for unsupported OS
	ErrUnsupportedOS = xerrors.New("unsupported os")

	drivers = map[string]Driver{
		fos.Alpine:       alpine.NewScanner(),
		fos.Alma:         alma.NewScanner(),
		fos.Amazon:       amazon.NewScanner(),
		fos.CBLMariner:   mariner.NewScanner(),
		fos.Debian:       debian.NewScanner(),
		fos.Ubuntu:       ubuntu.NewScanner(),
		fos.RedHat:       redhat.NewScanner(),
		fos.CentOS:       redhat.NewScanner(),
		fos.Rocky:        rocky.NewScanner(),
		fos.Oracle:       oracle.NewScanner(),
		fos.OpenSUSELeap: suse.NewScanner(suse.OpenSUSE),
		fos.SLES:         suse.NewScanner(suse.SUSEEnterpriseLinux),
		fos.Photon:       photon.NewScanner(),
		fos.Wolfi:        wolfi.NewScanner(),
		fos.Chainguard:   chainguard.NewScanner(),
		fos.Kylin:        ubuntu.NewScanner(),
	}
)

// RegisterDriver is defined for extensibility and not supposed to be used in Trivy.
func RegisterDriver(name string, driver Driver) {
	drivers[name] = driver
}

// Driver defines operations for OS package scan
type Driver interface {
	Detect(string, *ftypes.Repository, []ftypes.Package) ([]types.DetectedVulnerability, error)
	IsSupportedVersion(string, string) bool
}

// Detect detects the vulnerabilities
func Detect(_, osFamily, osName string, repo *ftypes.Repository, _ time.Time, pkgs []ftypes.Package) ([]types.DetectedVulnerability, bool, error) {
	driver, err := newDriver(osFamily)
	if err != nil {
		return nil, false, ErrUnsupportedOS
	}

	eosl := !driver.IsSupportedVersion(osFamily, osName)

	vulns, err := driver.Detect(osName, repo, pkgs)
	if err != nil {
		return nil, false, xerrors.Errorf("failed detection: %w", err)
	}

	return vulns, eosl, nil
}

func newDriver(osFamily string) (Driver, error) {
	if driver, ok := drivers[osFamily]; ok {
		return driver, nil
	}

	log.Logger.Warnf("unsupported os : %s", osFamily)
	return nil, ErrUnsupportedOS
}
