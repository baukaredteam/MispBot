package privacy

import (
"crypto/aes"
"crypto/cipher"
"crypto/rand"
"encoding/base64"
"encoding/hex"
"fmt"
"hash"
"io"
"net"
"net/url"
"regexp"
"strings"
"sync"
"time"
"unicode"

"github.com/google/uuid"
"golang.org/x/crypto/pbkdf2"
"golang.org/x/crypto/sha256"
)

type SensitivityLevel int

const (
SensitivityPublic SensitivityLevel = iota
SensitivityInternal
SensitivityConfidential
SensitivityRestricted
)

type TokenType string

const (
TokenTypeEmail    TokenType = "email"
TokenTypeDomain   TokenType = "domain"
TokenTypeIP       TokenType = "ip"
TokenTypeURL      TokenType = "url"
TokenTypeUsername TokenType = "username"
TokenTypeTicketID TokenType = "ticket_id"
TokenTypeJWT      TokenType = "jwt"
TokenTypeGeneric  TokenType = "generic"
)

type TokenMapping struct {
Token     string
Original  string
Type      TokenType
CreatedAt time.Time
ExpiresAt time.Time
UseCount  int
}

type PrivacyGateway struct {
mu            sync.RWMutex
tokens        map[string]*TokenMapping
encryptionKey []byte
salt          []byte
emailRegex    *regexp.Regexp
ipRegex       *regexp.Regexp
urlRegex      *regexp.Regexp
jwtRegex      *regexp.Regexp
ticketRegex   *regexp.Regexp
domainRegex   *regexp.Regexp
customDict    map[string]TokenType
dictMu        sync.RWMutex
}

func NewPrivacyGateway(encryptionKey []byte) (*PrivacyGateway, error) {
if len(encryptionKey) < 32 {
key := pbkdf2.Key(encryptionKey, []byte("phishguard-salt"), 100000, 32, sha256.New)
encryptionKey = key
}

pg := &PrivacyGateway{
tokens:        make(map[string]*TokenMapping),
encryptionKey: encryptionKey[:32],
salt:          []byte("phishguard-privacy-salt"),
customDict:    make(map[string]TokenType),
}

pg.emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
pg.ipRegex = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
pg.urlRegex = regexp.MustCompile(`https?://[^\s<>"{}|\\^\[\]]+`)
pg.jwtRegex = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
pg.ticketRegex = regexp.MustCompile(`(?i)(?:TICKET|INC|CASE|REQ)[-#]?[0-9]{6,}`)
pg.domainRegex = regexp.MustCompile(`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|biz|info|ru|de|fr|uk|cn|jp|br|au|in|it|nl|es|pl|tr|se|no|fi|dk|ch|at|be|cz|pt|gr|hu|ro|ua|il|za|mx|ar|cl|co|nz|sg|my|th|id|ph|vn|kr|tw|hk)`)

return pg, nil
}

func (pg *PrivacyGateway) AnalyzeSensitivity(text string) SensitivityLevel {
level := SensitivityPublic
emailMatches := pg.emailRegex.FindAllString(text, -1)
ipMatches := pg.ipRegex.FindAllString(text, -1)
jwtMatches := pg.jwtRegex.FindAllString(text, -1)

if len(jwtMatches) > 0 {
return SensitivityRestricted
}
if len(emailMatches) > 5 || len(ipMatches) > 3 {
return SensitivityConfidential
}
if len(emailMatches) > 0 || len(ipMatches) > 0 {
return SensitivityInternal
}
return level
}

func (pg *PrivacyGateway) MaskAndTokenize(text string) (string, []*TokenMapping, error) {
pg.mu.Lock()
defer pg.mu.Unlock()
var mappings []*TokenMapping
result := text

result, jwtMappings := pg.maskPattern(result, pg.jwtRegex, TokenTypeJWT)
mappings = append(mappings, jwtMappings...)
result, emailMappings := pg.maskPattern(result, pg.emailRegex, TokenTypeEmail)
mappings = append(mappings, emailMappings...)
result, ipMappings := pg.maskPattern(result, pg.ipRegex, TokenTypeIP)
mappings = append(mappings, ipMappings...)

return result, mappings, nil
}

func (pg *PrivacyGateway) maskPattern(text string, regex *regexp.Regexp, tokenType TokenType) (string, []*TokenMapping) {
var mappings []*TokenMapping
result := regex.ReplaceAllStringFunc(text, func(match string) string {
token := pg.generateToken(match, tokenType)
mapping := &TokenMapping{
Token:     token,
Original:  match,
Type:      tokenType,
CreatedAt: time.Now(),
ExpiresAt: time.Now().Add(24 * time.Hour),
UseCount:  0,
}
pg.tokens[token] = mapping
mappings = append(mappings, mapping)
return token
})
return result, mappings
}

func (pg *PrivacyGateway) generateToken(original string, tokenType TokenType) string {
id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(original+string(tokenType)))
prefix := string(tokenType)[:3]
if len(prefix) < 3 {
prefix = "tok"
}
return fmt.Sprintf("[%s-%s]", prefix, id.String()[:8])
}

func (pg *PrivacyGateway) EncryptValue(value string) (string, error) {
block, err := aes.NewCipher(pg.encryptionKey)
if err != nil {
return "", err
}
gcm, err := cipher.NewGCM(block)
if err != nil {
return "", err
}
nonce := make([]byte, gcm.NonceSize())
if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
return "", err
}
ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (pg *PrivacyGateway) DecryptValue(encrypted string) (string, error) {
block, err := aes.NewCipher(pg.encryptionKey)
if err != nil {
return "", err
}
gcm, err := cipher.NewGCM(block)
if err != nil {
return "", err
}
data, err := base64.StdEncoding.DecodeString(encrypted)
if err != nil {
return "", err
}
nonceSize := gcm.NonceSize()
if len(data) < nonceSize {
return "", fmt.Errorf("ciphertext too short")
}
nonce, ciphertext := data[:nonceSize], data[nonceSize:]
plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
if err != nil {
return "", err
}
return string(plaintext), nil
}

func ValidateIPAddress(ip string) (valid bool, isPrivate bool, isInternal bool) {
parsedIP := net.ParseIP(ip)
if parsedIP == nil {
return false, false, false
}
isPrivate = parsedIP.IsPrivate()
isLoopback := parsedIP.IsLoopback()
isLinkLocal := parsedIP.IsLinkLocalUnicast()
isInternal = isPrivate || isLoopback || isLinkLocal
return true, isPrivate, isInternal
}

func CalculateSimilarity(s1, s2 string) float64 {
if s1 == s2 {
return 1.0
}
len1, len2 := len(s1), len(s2)
if len1 == 0 || len2 == 0 {
return 0.0
}
matrix := make([][]int, len1+1)
for i := range matrix {
matrix[i] = make([]int, len2+1)
matrix[i][0] = i
}
for j := range matrix[0] {
matrix[0][j] = j
}
for i := 1; i <= len1; i++ {
for j := 1; j <= len2; j++ {
cost := 1
if s1[i-1] == s2[j-1] {
cost = 0
}
matrix[i][j] = minInt(
matrix[i-1][j]+1,
matrix[i][j-1]+1,
matrix[i-1][j-1]+cost,
)
}
}
distance := matrix[len1][len2]
maxLen := maxInt(len1, len2)
return 1.0 - float64(distance)/float64(maxLen)
}

func minInt(nums ...int) int {
m := nums[0]
for _, n := range nums[1:] {
if n < m {
m = n
}
}
return m
}

func maxInt(a, b int) int {
if a > b {
return a
}
return b
}

func HashSensitiveData(data string, salt []byte) string {
hash := pbkdf2.Key([]byte(data), salt, 100000, 32, sha256.New)
return hex.EncodeToString(hash)
}

func isInvisibleChar(r rune) bool {
if r <= 0x001F && r != 0x0009 && r != 0x000A && r != 0x000D {
return true
}
if r == 0x007F || r == 0x00AD {
return true
}
cat := unicode.Category(r)
return cat == unicode.Cc || cat == unicode.Cf
}
