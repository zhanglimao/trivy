package redhatbase

import (
	"bufio"
	"context"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/zhanglimao/trivy/pkg/fanal/analyzer"
	aos "github.com/zhanglimao/trivy/pkg/fanal/analyzer/os"
	"github.com/zhanglimao/trivy/pkg/fanal/types"
	"github.com/zhanglimao/trivy/pkg/fanal/utils"
	"golang.org/x/xerrors"
)

const redhatAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&redhatOSAnalyzer{})
}

var redhatRe = regexp.MustCompile(`(.*) release (V?\d[\d\.]*)`)

type redhatOSAnalyzer struct{}

func (a redhatOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	foundOS, err := a.parseRelease(input.Content)
	if err != nil {
		return nil, err
	}
	return &analyzer.AnalysisResult{
		OS: foundOS,
	}, nil

}

func (a redhatOSAnalyzer) parseRelease(r io.Reader) (types.OS, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return types.OS{}, xerrors.New("redhat: invalid redhat-release")
		}

		switch strings.ToLower(result[1]) {
		case "centos", "centos linux":
			return types.OS{Family: aos.CentOS, Name: result[2]}, nil
		case "rocky", "rocky linux":
			return types.OS{Family: aos.Rocky, Name: result[2]}, nil
		case "alma", "almalinux", "alma linux":
			return types.OS{Family: aos.Alma, Name: result[2]}, nil
		case "oracle", "oracle linux", "oracle linux server":
			return types.OS{Family: aos.Oracle, Name: result[2]}, nil
		case "fedora", "fedora linux":
			return types.OS{Family: aos.Fedora, Name: result[2]}, nil
		case "kylin", "kylin linux", "kylin linux advanced server":
			return types.OS{Family: aos.Kylin, Name: result[2]}, nil
		default:
			return types.OS{Family: aos.RedHat, Name: result[2]}, nil
		}
	}
	return types.OS{}, xerrors.Errorf("redhatbase: %w", aos.AnalyzeOSError)
}

func (a redhatOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a redhatOSAnalyzer) requiredFiles() []string {
	return []string{"etc/redhat-release", "etc/kylin-release"}
}

func (a redhatOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRedHatBase
}

func (a redhatOSAnalyzer) Version() int {
	return redhatAnalyzerVersion
}
