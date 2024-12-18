package redhatbase

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/zhanglimao/trivy/pkg/fanal/analyzer"
	aos "github.com/zhanglimao/trivy/pkg/fanal/analyzer/os"
	"github.com/zhanglimao/trivy/pkg/fanal/types"
	"github.com/zhanglimao/trivy/pkg/fanal/utils"
	"golang.org/x/xerrors"
)

const kylinAnalyzerVersion = 1

func init() {
	analyzer.RegisterAnalyzer(&kylinAnalyzer{})
}

type kylinAnalyzer struct{}

func (a kylinAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		result := redhatRe.FindStringSubmatch(strings.TrimSpace(line))
		if len(result) != 3 {
			return nil, xerrors.New("kylin: invalid kylin-release")
		}

		switch strings.ToLower(result[1]) {
		case "kylin", "kylin linux", "kylin linux advanced server":
			return &analyzer.AnalysisResult{
				OS: types.OS{Family: aos.Kylin, Name: result[2]},
			}, nil
		}
	}

	return nil, xerrors.Errorf("kylin: %v", aos.AnalyzeOSError)
}

func (a kylinAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, a.requiredFiles())
}

func (a kylinAnalyzer) requiredFiles() []string {
	return []string{"etc/kylin-release"}
}

func (a kylinAnalyzer) Type() analyzer.Type {
	return analyzer.TypeKylin
}

func (a kylinAnalyzer) Version() int {
	return kylinAnalyzerVersion
}
