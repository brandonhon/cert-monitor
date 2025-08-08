#!/bin/bash
# Apply Phase 1 changes to main.go using sed

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🔧 Applying Phase 1 changes to main.go...${NC}"

# Check if main.go exists
if [ ! -f "main.go" ]; then
    echo -e "${RED}❌ main.go not found${NC}"
    exit 1
fi

# Create backup
cp main.go main.go.phase1-backup
echo -e "${GREEN}✅ Backup created: main.go.phase1-backup${NC}"

# Step 1: Add imports after the existing imports
echo -e "${BLUE}📦 Adding new imports...${NC}"
sed -i.tmp '/log "github.com\/sirupsen\/logrus"/a\
	"github.com/brandonhon/cert-monitor/internal/config"\
	"github.com/brandonhon/cert-monitor/pkg/utils"' main.go && rm main.go.tmp

# Step 2: Update type references
echo -e "${BLUE}🔄 Updating type references...${NC}"
sed -i.tmp 's/\*Config/\*config.Config/g' main.go && rm main.go.tmp
sed -i.tmp 's/config \*Config/config \*config.Config/g' main.go && rm main.go.tmp

# Step 3: Replace function calls and constants with utils package
echo -e "${BLUE}🔧 Updating utility function calls and constants...${NC}"
sed -i.tmp 's/isWeakKey(/utils.IsWeakKey(/g' main.go && rm main.go.tmp
sed -i.tmp 's/isDeprecatedSigAlg(/utils.IsDeprecatedSigAlg(/g' main.go && rm main.go.tmp
sed -i.tmp 's/determineIssuerCode(/utils.DetermineIssuerCode(/g' main.go && rm main.go.tmp
sed -i.tmp 's/sanitizeLabelValue(/utils.SanitizeLabelValue(/g' main.go && rm main.go.tmp
sed -i.tmp 's/validateFileAccess(/utils.ValidateFileAccess(/g' main.go && rm main.go.tmp
sed -i.tmp 's/validateDirectoryAccess(/utils.ValidateDirectoryAccess(/g' main.go && rm main.go.tmp
sed -i.tmp 's/isCertificateFile(/utils.IsCertificateFile(/g' main.go && rm main.go.tmp
sed -i.tmp 's/isWindows(/utils.IsWindows(/g' main.go && rm main.go.tmp

# Update constants
sed -i.tmp 's/maxSANsExported/utils.MaxSANsExported/g' main.go && rm main.go.tmp
sed -i.tmp 's/maxLabelLength/utils.MaxLabelLength/g' main.go && rm main.go.tmp
sed -i.tmp 's/defaultPort/utils.DefaultPort/g' main.go && rm main.go.tmp
sed -i.tmp 's/defaultBindAddress/utils.DefaultBindAddress/g' main.go && rm main.go.tmp
sed -i.tmp 's/defaultWorkers/utils.DefaultWorkers/g' main.go && rm main.go.tmp
sed -i.tmp 's/defaultExpiryDays/utils.DefaultExpiryDays/g' main.go && rm main.go.tmp
sed -i.tmp 's/maxBackoff/utils.MaxBackoff/g' main.go && rm main.go.tmp
sed -i.tmp 's/minDiskSpaceBytes/utils.MinDiskSpaceBytes/g' main.go && rm main.go.tmp
sed -i.tmp 's/cacheWriteTimeout/utils.CacheWriteTimeout/g' main.go && rm main.go.tmp
sed -i.tmp 's/watcherDebounce/utils.WatcherDebounce/g' main.go && rm main.go.tmp
sed -i.tmp 's/runtimeMetricsInterval/utils.RuntimeMetricsInterval/g' main.go && rm main.go.tmp
sed -i.tmp 's/gracefulShutdownTimeout/utils.GracefulShutdownTimeout/g' main.go && rm main.go.tmp

# Update issuer codes
sed -i.tmp 's/IssuerCodeDigiCert/utils.IssuerCodeDigiCert/g' main.go && rm main.go.tmp
sed -i.tmp 's/IssuerCodeAmazon/utils.IssuerCodeAmazon/g' main.go && rm main.go.tmp
sed -i.tmp 's/IssuerCodeOther/utils.IssuerCodeOther/g' main.go && rm main.go.tmp
sed -i.tmp 's/IssuerCodeSelfSigned/utils.IssuerCodeSelfSigned/g' main.go && rm main.go.tmp

# Step 4: Replace config function calls
echo -e "${BLUE}⚙️  Updating configuration function calls...${NC}"
sed -i.tmp 's/LoadConfig(/loadConfigFromFile(/g' main.go && rm main.go.tmp
sed -i.tmp 's/DefaultConfig()/config.Default()/g' main.go && rm main.go.tmp
sed -i.tmp 's/validateConfig(/config.Validate(/g' main.go && rm main.go.tmp

# Step 5: Add the new loadConfigFromFile function
echo -e "${BLUE}➕ Adding loadConfigFromFile function...${NC}"
cat >> main.go << 'EOF'

// loadConfigFromFile loads configuration from file using new config package
func loadConfigFromFile(configFile string) error {
	cfg, err := config.Load(configFile)
	if err != nil {
		return err
	}
	
	globalState.setConfig(cfg)
	
	log.WithFields(log.Fields{
		"config_file": configFile,
		"cert_dirs":   len(cfg.CertDirs),
		"port":        cfg.Port,
		"workers":     cfg.NumWorkers,
	}).Info("Configuration loaded successfully")
	
	return nil
}
EOF

echo -e "${GREEN}✅ Phase 1 function call updates completed${NC}"
echo ""
echo -e "${YELLOW}⚠️  Manual steps still required:${NC}"
echo "1. Remove the Config struct definition from main.go"
echo "2. Remove utility function definitions (isWeakKey, isDeprecatedSigAlg, etc.)"
echo "3. Remove configuration function definitions (LoadConfig, DefaultConfig, etc.)"
echo "4. Remove validation function definitions"
echo "5. Remove constants that are now in utils package"
echo ""
echo "Use this script to find functions to remove:"
echo ""
cat << 'EOF'
# Find functions that should be removed
echo "Functions to remove from main.go:"
grep -n "^func isWeakKey\|^func isDeprecatedSigAlg\|^func determineIssuerCode\|^func sanitizeLabelValue\|^func isCertificateFile\|^func isWindows\|^func LoadConfig\|^func DefaultConfig\|^func validateConfig\|^func validateCertDirectories\|^func validateNetworkConfig\|^func validateWorkerConfig\|^func validateTLSConfig\|^func validateFileConfig\|^func validateFileAccess\|^func validateDirectoryAccess\|^func validateDirectoryCreation\|^func defaultLogPath" main.go

echo ""
echo "Config struct to remove:"
grep -n "^type Config struct" main.go

echo ""
echo "Constants to remove (that are now in utils):"
grep -n "maxSANsExported\|maxLabelLength\|defaultPort\|defaultBindAddress\|defaultWorkers\|defaultExpiryDays\|IssuerCodeDigiCert\|IssuerCodeAmazon\|IssuerCodeOther\|IssuerCodeSelfSigned" main.go
EOF

echo ""
echo -e "${BLUE}💡 Tip: After manual removal, run:${NC}"
echo "go build -o test . && rm test"
echo "to verify compilation works"