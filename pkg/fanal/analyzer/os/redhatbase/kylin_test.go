package redhatbase

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zhanglimao/trivy/pkg/fanal/analyzer"
	"github.com/zhanglimao/trivy/pkg/fanal/types"
)

func Test_kylinOSAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/kylin/kylin-release",
			want: &analyzer.AnalysisResult{
				OS: types.OS{Family: "kylin", Name: "V10"},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/not_redhatbase/empty",
			wantErr:   "kylin: unable to analyze OS information",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := kylinAnalyzer{}
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()
			ctx := context.Background()

			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: "etc/kylin-release",
				Content:  f,
			})
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
