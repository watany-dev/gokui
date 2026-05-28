package scan

import (
	"os"
	"regexp"
)

var (
	curlPipePattern                  = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sh|bash|zsh|pwsh|powershell|python3?|node|ruby|perl)\b`)
	curlPipeSourceStdInExecPattern   = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:(?:builtin|command)(?:\s*--|\s+-p(?:\s*--)?|-p(?:\s*--)?)?\s+)*(?:source|\.)\s+(?:\\*['"])?(?:/+dev/+stdin|/+dev/+fd/+0+|/+proc/+(?:self|thread-self|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$\{[a-z_][a-z0-9_]*:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[a-z_][a-z0-9_]*-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\}|\$\{[0-9]{1,10}:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[0-9]{1,10}-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|[0-9]{1,10})(?:/+task/+(?:\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$\{[a-z_][a-z0-9_]*:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[a-z_][a-z0-9_]*-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\}|\$\{[0-9]{1,10}:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[0-9]{1,10}-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|[0-9]{1,10}))?/+fd/+0+|-)(?:\\*['"])?(?:\s|$|[,&;|)"'\x60])`)
	curlSubshellExecPattern          = regexp.MustCompile(`(?i)\b(?:sh|bash|zsh|source|pwsh|powershell|eval|python3?|node|ruby|perl)\b[^\n]{0,200}\$\(\s*(?:curl|wget)\b`)
	curlBacktickExecPattern          = regexp.MustCompile("(?i)\\b(?:sh|bash|zsh|source|pwsh|powershell|eval|python3?|node|ruby|perl)\\b[^\\n]{0,200}`\\s*(?:curl|wget)\\b")
	curlDotSubshellExecPattern       = regexp.MustCompile(`(?i)(?:^|[;&|]\s*)\.\s+\$\(\s*(?:curl|wget)\b`)
	curlDotBacktickExecPattern       = regexp.MustCompile("(?i)(?:^|[;&|]\\s*)\\.\\s+`\\s*(?:curl|wget)\\b")
	powerShellRemoteEvalPattern      = regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b[^\n]{0,260}(?:\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl(?:\.exe)?|wget(?:\.exe)?)\b[^\n]{0,220}https?://|\bdownload(?:string|data)\b\s*\(\s*['"]?https?://)`)
	powerShellFetchEvalPattern       = regexp.MustCompile(`(?i)(?:\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl(?:\.exe)?|wget(?:\.exe)?)\b[^\n]{0,260}https?://[^\n]{0,260}\b(?:iex|invoke-expression)\b|\bdownload(?:string|data)\b\s*\(\s*['"]?https?://[^\n]{0,260}\b(?:iex|invoke-expression)\b)`)
	pythonRemoteExecPattern          = regexp.MustCompile(`(?i)\b(?:exec|eval)\s*\(\s*(?:requests\.get\s*\(\s*['"]https?://[^'"]+['"]\s*\)\.text|urllib\.request\.urlopen\s*\(\s*['"]https?://[^'"]+['"]\s*\)\.read\s*\(\s*\))`)
	pythonBase64ExecPattern          = regexp.MustCompile(`(?i)\b(?:exec|eval)\s*\(\s*(?:__import__\(\s*['"]base64['"]\s*\)\.b64decode|base64\.b64decode|b64decode)\s*\(`)
	pythonHexExecPattern             = regexp.MustCompile(`(?i)\b(?:exec|eval)\s*\(\s*(?:bytes\.fromhex|bytearray\.fromhex|binascii\.unhexlify)\s*\(`)
	nodeRemoteEvalPattern            = regexp.MustCompile(`(?i)\beval\s*\(\s*(?:(?:await\s+)?fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)|(?:await\s+)?\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\)|\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\))`)
	nodeRemoteFunctionExecPattern    = regexp.MustCompile(`(?i)\bnew\s+function\s*\(\s*(?:(?:await\s+)?\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\)|\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\))\s*\)\s*\(`)
	nodeBase64EvalPattern            = regexp.MustCompile(`(?i)\b(?:eval|new\s+function)\s*\(\s*(?:atob\s*\(|buffer\s*\.\s*from\s*\([^)\n]{0,260}['"]base64['"]\s*\)\s*\.toString\s*\()`)
	nodeHexEvalPattern               = regexp.MustCompile(`(?i)\b(?:eval|new\s+function)\s*\(\s*buffer\s*\.\s*from\s*\([^)\n]{0,260}['"]hex['"]\s*\)\s*\.toString\s*\(`)
	perlBase64EvalPattern            = regexp.MustCompile(`(?i)\beval\b[^\n]{0,260}\b(?:decode_base64|mime::base64::decode_base64)\s*\(`)
	perlHexEvalPattern               = regexp.MustCompile(`(?i)\beval\b[^\n]{0,260}\bpack\s*\(\s*['"]h\*['"]\s*,`)
	rubyBase64EvalPattern            = regexp.MustCompile(`(?i)\beval\s*\([^)\n]{0,260}(?:base64\.decode64|strict_decode64|urlsafe_decode64)\s*\(`)
	rubyHexEvalPattern               = regexp.MustCompile(`(?i)\beval\s*\([^)\n]{0,260}\.pack\s*\(\s*['"]h\*['"]`)
	rubyRemoteEvalPattern            = regexp.MustCompile(`(?i)\beval\s*\(\s*(?:net::http\.get\s*\(\s*uri\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)|uri\.open\s*\(\s*['"]https?://[^'"]+['"]\s*\)\.read)`)
	base64PipeExec                   = regexp.MustCompile(`(?i)\b(?:base64|openssl\s+base64)\b[^\n|]{0,300}\|\s*(?:sh|bash|zsh|pwsh|powershell|python|node)\b`)
	base64PipeSourceStdInExec        = regexp.MustCompile(`(?i)\b(?:base64|openssl\s+base64)\b[^\n|]{0,300}\|\s*(?:(?:builtin|command)(?:\s*--|\s+-p(?:\s*--)?|-p(?:\s*--)?)?\s+)*(?:source|\.)\s+(?:\\*['"])?(?:/+dev/+stdin|/+dev/+fd/+0+|/+proc/+(?:self|thread-self|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$\{[a-z_][a-z0-9_]*:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[a-z_][a-z0-9_]*-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\}|\$\{[0-9]{1,10}:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[0-9]{1,10}-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|[0-9]{1,10})(?:/+task/+(?:\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$\{[a-z_][a-z0-9_]*:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[a-z_][a-z0-9_]*-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\}|\$\{[0-9]{1,10}:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[0-9]{1,10}-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|[0-9]{1,10}))?/+fd/+0+|-)(?:\\*['"])?(?:\s|$|[,&;|)"'\x60])`)
	base64SubshellExec               = regexp.MustCompile(`(?i)\b(?:sh|bash|zsh|source|pwsh|powershell|eval|python3?|node|ruby|perl)\b[^\n]{0,220}\$\([^)\n]{0,260}\b(?:base64|openssl\s+base64)\b[^)\n]{0,200}\s(?:-d|--decode)\b[^)\n]{0,120}\)`)
	base64DotSubshellExec            = regexp.MustCompile(`(?i)(?:^|[;&|]\s*)\.\s+\$\([^)\n]{0,260}\b(?:base64|openssl\s+base64)\b[^)\n]{0,200}\s(?:-d|--decode)\b[^)\n]{0,120}\)`)
	powerShellFromBase64ExecPattern  = regexp.MustCompile(`(?i)(?:\b(?:iex|invoke-expression)\b[^\n]{0,320}\bfrombase64string\s*\(|\bfrombase64string\s*\([^\n]{0,320}\b(?:iex|invoke-expression)\b)`)
	hexPipeExec                      = regexp.MustCompile(`(?i)\b(?:xxd\s+-r(?:\s+-p)?|unhexlify|fromhex|hexdecode)\b[^\n|]{0,300}\|\s*(?:sh|bash|zsh|pwsh|powershell|python|node)\b`)
	hexPipeSourceStdInExec           = regexp.MustCompile(`(?i)\b(?:xxd\s+-r(?:\s+-p)?|unhexlify|fromhex|hexdecode)\b[^\n|]{0,300}\|\s*(?:(?:builtin|command)(?:\s*--|\s+-p(?:\s*--)?|-p(?:\s*--)?)?\s+)*(?:source|\.)\s+(?:\\*['"])?(?:/+dev/+stdin|/+dev/+fd/+0+|/+proc/+(?:self|thread-self|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$\{[a-z_][a-z0-9_]*:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[a-z_][a-z0-9_]*-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\}|\$\{[0-9]{1,10}:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[0-9]{1,10}-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|[0-9]{1,10})(?:/+task/+(?:\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$\{[a-z_][a-z0-9_]*:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[a-z_][a-z0-9_]*-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\}|\$\{[0-9]{1,10}:-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|\$\{[0-9]{1,10}-(?:[a-z0-9_]+|\$\$|\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*\}|\$[0-9]{1,10}|\$\{[0-9]{1,10}\})\}|[0-9]{1,10}))?/+fd/+0+|-)(?:\\*['"])?(?:\s|$|[,&;|)"'\x60])`)
	hexSubshellExec                  = regexp.MustCompile(`(?i)\b(?:sh|bash|zsh|source|pwsh|powershell|eval|python3?|node|ruby|perl)\b[^\n]{0,220}\$\([^)\n]{0,260}\b(?:xxd\s+-r(?:\s+-p)?|unhexlify|fromhex|hexdecode)\b[^)\n]{0,200}\)`)
	hexDotSubshellExec               = regexp.MustCompile(`(?i)(?:^|[;&|]\s*)\.\s+\$\([^)\n]{0,260}\b(?:xxd\s+-r(?:\s+-p)?|unhexlify|fromhex|hexdecode)\b[^)\n]{0,200}\)`)
	powerShellFromHexExecPattern     = regexp.MustCompile(`(?i)(?:\b(?:iex|invoke-expression)\b[^\n]{0,320}\bfromhexstring\s*\(|\bfromhexstring\s*\([^\n]{0,320}\b(?:iex|invoke-expression)\b)`)
	encodedCmdExec                   = regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,240}\s-(?:encodedcommand|enc)\s+[a-z0-9+/=]{12,}\b`)
	encodedCmdExecVariableArg        = regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,240}\s-(?:encodedcommand|enc)\s+(?:\$[a-z0-9_:{\}\.\(\)\-]+|%[a-z0-9_]+%)`)
	shellAssignDefaultNamedPattern   = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):=([^}\n]+)\}`)
	shellAssignDefaultPosPattern     = regexp.MustCompile(`\$\{([0-9]{1,10}):=([^}\n]+)\}`)
	shellAssignNamedPattern          = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)=([^}\n]+)\}`)
	shellAssignPosPattern            = regexp.MustCompile(`\$\{([0-9]{1,10})=([^}\n]+)\}`)
	shellSetSubDefaultNamedPattern   = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):\+([^}\n]+)\}`)
	shellSetSubDefaultPosPattern     = regexp.MustCompile(`\$\{([0-9]{1,10}):\+([^}\n]+)\}`)
	shellSetSubNamedPattern          = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\+([^}\n]+)\}`)
	shellSetSubPosPattern            = regexp.MustCompile(`\$\{([0-9]{1,10})\+([^}\n]+)\}`)
	shellEmptySetSubDefaultNamed     = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):\+\}`)
	shellEmptySetSubDefaultPos       = regexp.MustCompile(`\$\{([0-9]{1,10}):\+\}`)
	shellEmptySetSubNamedPattern     = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\+\}`)
	shellEmptySetSubPosPattern       = regexp.MustCompile(`\$\{([0-9]{1,10})\+\}`)
	shellErrorDefaultNamedPattern    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):\?([^}\n]+)\}`)
	shellErrorDefaultPosPattern      = regexp.MustCompile(`\$\{([0-9]{1,10}):\?([^}\n]+)\}`)
	shellErrorNamedPattern           = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\?([^}\n]+)\}`)
	shellErrorPosPattern             = regexp.MustCompile(`\$\{([0-9]{1,10})\?([^}\n]+)\}`)
	shellEmptyColonDashNamedPattern  = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):-\}`)
	shellEmptyColonDashPosPattern    = regexp.MustCompile(`\$\{([0-9]{1,10}):-\}`)
	shellEmptyDashNamedPattern       = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)-\}`)
	shellEmptyDashPosPattern         = regexp.MustCompile(`\$\{([0-9]{1,10})-\}`)
	shellEmptyAssignDefaultNamed     = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):=\}`)
	shellEmptyAssignDefaultPos       = regexp.MustCompile(`\$\{([0-9]{1,10}):=\}`)
	shellEmptyAssignNamedPattern     = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)=\}`)
	shellEmptyAssignPosPattern       = regexp.MustCompile(`\$\{([0-9]{1,10})=\}`)
	shellEmptyErrorDefaultNamed      = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):\?\}`)
	shellEmptyErrorDefaultPos        = regexp.MustCompile(`\$\{([0-9]{1,10}):\?\}`)
	shellEmptyErrorNamedPattern      = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\?\}`)
	shellEmptyErrorPosPattern        = regexp.MustCompile(`\$\{([0-9]{1,10})\?\}`)
	shellIndirectNamedPattern        = regexp.MustCompile(`\$\{!([A-Za-z_][A-Za-z0-9_]*)\}`)
	shellIndirectPosPattern          = regexp.MustCompile(`\$\{!([0-9]{1,10})\}`)
	shellTrimPrefixNamedPattern      = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)##[^}\n]+\}`)
	shellTrimPrefixPosPattern        = regexp.MustCompile(`\$\{([0-9]{1,10})##[^}\n]+\}`)
	shellTrimPrefixShortNamed        = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)#[^}\n]+\}`)
	shellTrimPrefixShortPos          = regexp.MustCompile(`\$\{([0-9]{1,10})#[^}\n]+\}`)
	shellTrimSuffixNamedPattern      = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)%%[^}\n]+\}`)
	shellTrimSuffixPosPattern        = regexp.MustCompile(`\$\{([0-9]{1,10})%%[^}\n]+\}`)
	shellTrimSuffixShortNamed        = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)%[^}\n]+\}`)
	shellTrimSuffixShortPos          = regexp.MustCompile(`\$\{([0-9]{1,10})%[^}\n]+\}`)
	shellSubstringNamedNestedPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):\$\{(?:[^{}\n]|\$\{[^{}\n]+\})+\}(?::\$\{(?:[^{}\n]|\$\{[^{}\n]+\})+\})?\}`)
	shellSubstringPosNestedPattern   = regexp.MustCompile(`\$\{([0-9]{1,10}):\$\{(?:[^{}\n]|\$\{[^{}\n]+\})+\}(?::\$\{(?:[^{}\n]|\$\{[^{}\n]+\})+\})?\}`)
	shellSubstringNamedVarPattern    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*:\s*[A-Za-z_][A-Za-z0-9_]*)?\}`)
	shellSubstringPosVarPattern      = regexp.MustCompile(`\$\{([0-9]{1,10}):\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*:\s*[A-Za-z_][A-Za-z0-9_]*)?\}`)
	shellSubstringNamedPattern       = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):(?:[0-9]{1,10}|\s+[0-9]{1,10}|\s+-[0-9]{1,10})(?:\s*:\s*-?[0-9]{1,10})?\}`)
	shellSubstringPosPattern         = regexp.MustCompile(`\$\{([0-9]{1,10}):(?:[0-9]{1,10}|\s+[0-9]{1,10}|\s+-[0-9]{1,10})(?:\s*:\s*-?[0-9]{1,10})?\}`)
	shellTransformNamedPattern       = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)@[A-Za-z]\}`)
	shellTransformPosPattern         = regexp.MustCompile(`\$\{([0-9]{1,10})@[A-Za-z]\}`)
	shellCaseUpperNamedWithPattern   = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\^\^[^}\n]+\}`)
	shellCaseUpperPosWithPattern     = regexp.MustCompile(`\$\{([0-9]{1,10})\^\^[^}\n]+\}`)
	shellCaseLowerNamedWithPattern   = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*),,[^}\n]+\}`)
	shellCaseLowerPosWithPattern     = regexp.MustCompile(`\$\{([0-9]{1,10}),,[^}\n]+\}`)
	shellCaseUpperFirstNamedPattern  = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\^[^}\n]+\}`)
	shellCaseUpperFirstPosPattern    = regexp.MustCompile(`\$\{([0-9]{1,10})\^[^}\n]+\}`)
	shellCaseLowerFirstNamedPattern  = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*),[^}\n]+\}`)
	shellCaseLowerFirstPosPattern    = regexp.MustCompile(`\$\{([0-9]{1,10}),[^}\n]+\}`)
	shellCaseUpperNamedPattern       = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\^\^\}`)
	shellCaseUpperPosPattern         = regexp.MustCompile(`\$\{([0-9]{1,10})\^\^\}`)
	shellCaseLowerNamedPattern       = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*),,\}`)
	shellCaseLowerPosPattern         = regexp.MustCompile(`\$\{([0-9]{1,10}),,\}`)
	shellCaseUpperFirstNamed         = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\^\}`)
	shellCaseUpperFirstPos           = regexp.MustCompile(`\$\{([0-9]{1,10})\^\}`)
	shellCaseLowerFirstNamed         = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*),\}`)
	shellCaseLowerFirstPos           = regexp.MustCompile(`\$\{([0-9]{1,10}),\}`)
	shellLengthNamedPattern          = regexp.MustCompile(`\$\{#([A-Za-z_][A-Za-z0-9_]*)\}`)
	shellLengthPosPattern            = regexp.MustCompile(`\$\{#([0-9]{1,10})\}`)
	shellProcDollarSubstringNamed    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):\$\$(?:\s*:\s*\$\$)?\}`)
	shellProcDollarSubstringPos      = regexp.MustCompile(`\$\{([0-9]{1,10}):\$\$(?:\s*:\s*\$\$)?\}`)
	shellArithmeticExpansionPattern  = regexp.MustCompile(`\$\(\([^\n]{1,120}?\)\)`)
	shellLegacyArithmeticPattern     = regexp.MustCompile(`\$\[[^\]\n]{1,120}\]`)
	shellAnsiCQuotePattern           = regexp.MustCompile(`\$'[^'\n]{1,120}'`)

	promptOverridePattern = regexp.MustCompile(`(?i)\b(?:ignore|override|bypass)\b.{0,80}\b(?:previous|prior|system|higher|earlier)\b.{0,40}\b(?:instruction|instructions|prompt|prompts)\b`)

	externalBinaryPattern              = regexp.MustCompile(`(?i)\bhttps?://\S+\.(?:zip|exe|msi|dmg|pkg|tar\.gz|tgz)\b`)
	urlPattern                         = regexp.MustCompile(`(?i)(?:https?://|//)[^\s<>"')\]]+`)
	ipv6URLPattern                     = regexp.MustCompile(`(?i)(?:https?://|//)\[[0-9a-z:._%-]+\](?::\d+)?[^\s<>"')]*`)
	rawHTMLPattern                     = regexp.MustCompile(`(?i)<\s*(?:script|iframe|object|embed|form|link|meta|img|svg|video|audio)\b`)
	markdownLinkPattern                = regexp.MustCompile(`\[(?P<label>[^\]]+)\]\((?P<target>[^)\n]+)\)`)
	markdownReferenceLinkPattern       = regexp.MustCompile(`\[(?P<label>[^\]]+)\][ \t]*\[(?P<ref>[^\]]*)\]`)
	markdownShortcutReferencePattern   = regexp.MustCompile(`\[(?P<label>[^\]]+)\]`)
	markdownReferenceDefinitionPattern = regexp.MustCompile(`^\s{0,3}\[(?P<ref>[^\]]+)\]:\s*(?P<target>.*?)\s*$`)
	passwordArchivePattern             = regexp.MustCompile(`(?i)(?:\b(?:password|passphrase|passwd|encrypted)\b.{0,80}\b(?:zip|7z|rar|archive|tar|tgz|tar\.gz)\b|\b(?:zip|7z|rar|archive|tar|tgz|tar\.gz)\b.{0,80}\b(?:password|passphrase|passwd|encrypted)\b)`)
	goSemverExactPattern               = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:-[0-9a-z.-]+)?(?:\+[0-9a-z.-]+)?$`)
	goPseudoVersionPattern             = regexp.MustCompile(`^v\d+\.\d+\.\d+-\d{14}-[0-9a-f]{12}$`)
	hexCommitRefPattern                = regexp.MustCompile(`^[0-9a-f]{12,40}$`)
	remoteScriptImportPattern          = regexp.MustCompile(`(?i)\b(?:source|bash|sh|zsh)\b\s*<\(\s*(?:curl|wget)\b`)
	remoteScriptDotImport              = regexp.MustCompile(`(?i)(?:^|[;&|]\s*)\.\s*<\(\s*(?:curl|wget)\b`)

	fakePrereqPattern = regexp.MustCompile(`(?i)\b(?:required|required prerequisite|you must|before use)\b.{0,120}\b(?:download|install)\b.{0,200}\b(?:run|execute|bash|sh|powershell|chmod \+x)\b`)
)

var promptOverridePhrases = [][]string{
	{"ignore", "previous", "instructions"},
	{"ignore", "all", "previous", "instructions"},
	{"disregard", "previous", "instructions"},
	{"override", "system", "prompt"},
	{"bypass", "safety", "instructions"},
}

type scanTarget struct {
	Absolute string
	Relative string
	Kind     string
	Info     os.FileInfo
}

type encodedCandidate struct {
	kind  string
	value string
}

var scriptLikeExtensions = map[string]struct{}{
	".sh":   {},
	".bash": {},
	".zsh":  {},
	".ps1":  {},
	".bat":  {},
	".cmd":  {},
	".py":   {},
	".js":   {},
	".jsx":  {},
	".ts":   {},
	".tsx":  {},
	".mjs":  {},
	".cjs":  {},
	".psm1": {},
	".psd1": {},
	".rb":   {},
	".pl":   {},
	".pm":   {},
	".go":   {},
}

var manifestLikeFiles = map[string]struct{}{
	"package.json":     {},
	"pyproject.toml":   {},
	"requirements.txt": {},
	"uv.lock":          {},
	"go.mod":           {},
	"gemfile":          {},
	"deno.json":        {},
	"deno.jsonc":       {},
}

var urlShortenerHosts = map[string]struct{}{
	"bit.ly":      {},
	"tinyurl.com": {},
	"t.co":        {},
	"goo.gl":      {},
	"ow.ly":       {},
	"is.gd":       {},
	"buff.ly":     {},
	"cutt.ly":     {},
	"rb.gy":       {},
	"shorturl.at": {},
}

var pasteSiteHosts = map[string]struct{}{
	"pastebin.com":               {},
	"hastebin.com":               {},
	"ghostbin.com":               {},
	"dpaste.com":                 {},
	"gist.github.com":            {},
	"gist.githubusercontent.com": {},
}

var homeConfigPathHints = []string{
	"~/.bashrc",
	"~/.zshrc",
	"~/.profile",
	"~/.bash_profile",
	"~/.config/fish/config.fish",
	"~/.ssh/config",
	"~/.ssh/authorized_keys",
	"~/library/launchagents/",
	"/etc/profile",
	"/etc/bash.bashrc",
	"/etc/zsh/zshrc",
	"/etc/cron.d/",
	"/etc/cron.daily/",
	"/etc/cron.hourly/",
	"/etc/cron.weekly/",
	"/etc/cron.monthly/",
	"/var/spool/cron/",
}

var secretPathHints = []string{
	".env",
	"~/.ssh/",
	"/.ssh/",
	"~/.aws/",
	"/.aws/",
	"id_rsa",
	"id_ed25519",
	"credentials",
	"api_key",
	"token",
	"cookies",
	"keychain",
	"wallet",
}

var secretExfilNetworkCommand = regexp.MustCompile(`(?i)\b(?:curl|wget|invoke-webrequest|invoke-restmethod|requests\.post|netcat|nc)\b`)
var bashWildcardPermissionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\ballowed(?:[_ -]?tools?)\b.*\bbash\b.*(?:\*|\ball\b)`),
	regexp.MustCompile(`(?i)\bbash\b.*(?:\*|\ball\b).*allowed(?:[_ -]?tools?)\b`),
	regexp.MustCompile(`(?i)\btool(?:[_ -]?permissions?)\b.*\bbash\b.*(?:\*|\ball\b)`),
	regexp.MustCompile(`(?i)\bbash\s*\(\s*\*\s*\)`),
}

// confusableFilenameRunes maps a conservative subset of Cyrillic/Greek homoglyphs
// that are commonly used to visually mimic ASCII letters in filenames.
var confusableFilenameRunes = map[rune]rune{
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'У': 'Y',
	'Ԁ': 'D', 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ԁ': 'd',
	'Һ': 'H', 'һ': 'h', 'Ӏ': 'I', 'ӏ': 'l', 'Ԝ': 'W', 'ԝ': 'w',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	'Ϲ': 'C',
	'α': 'a', 'β': 'b', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'y', 'χ': 'x',
	'ϲ': 'c',
}

// Deno flags that require a following split value when provided without `=`.
var denoRequiredValueFlags = map[string]struct{}{
	"-c":                       {},
	"--config":                 {},
	"--import-map":             {},
	"--conditions":             {},
	"--host":                   {},
	"--port":                   {},
	"--location":               {},
	"--cert":                   {},
	"--preload":                {},
	"--import":                 {},
	"--require":                {},
	"--seed":                   {},
	"--package":                {},
	"--strace-ops":             {},
	"--strace-filter":          {},
	"--ext":                    {},
	"--log-level":              {},
	"-L":                       {},
	"--v8-flags":               {},
	"--cpu-prof-dir":           {},
	"--cpu-prof-interval":      {},
	"--cpu-prof-name":          {},
	"--node-modules-linker":    {},
	"--minimum-dependency-age": {},
	"--entrypoint":             {},
	"-e":                       {},
	"-n":                       {},
	"--name":                   {},
	"--root":                   {},
	"-p":                       {},
}

// Deno flags that may optionally consume a split value token.
var denoOptionalValueFlags = map[string]struct{}{
	"--reload":           {},
	"-r":                 {},
	"--frozen":           {},
	"--check":            {},
	"--no-check":         {},
	"--coverage":         {},
	"--inspect":          {},
	"--inspect-brk":      {},
	"--inspect-wait":     {},
	"--watch":            {},
	"--watch-exclude":    {},
	"--watch-hmr":        {},
	"--tunnel":           {},
	"-t":                 {},
	"--vendor":           {},
	"--lock":             {},
	"--env-file":         {},
	"--node-modules-dir": {},
	"--install-alias":    {},
	"--allow-scripts":    {},
	"--allow-import":     {},
	"-I":                 {},
	"--allow-read":       {},
	"-R":                 {},
	"--allow-write":      {},
	"-W":                 {},
	"--allow-net":        {},
	"-N":                 {},
	"--allow-env":        {},
	"-E":                 {},
	"--allow-run":        {},
	"--allow-ffi":        {},
	"--allow-sys":        {},
	"-S":                 {},
	"--deny-read":        {},
	"--deny-write":       {},
	"--deny-net":         {},
	"--deny-env":         {},
	"--deny-run":         {},
	"--deny-ffi":         {},
	"--deny-import":      {},
	"--deny-sys":         {},
}

var denoOptionalValueValidatorsRequiringCandidate = map[string]func(string) bool{
	"--reload":        isDenoReloadValue,
	"-r":              isDenoReloadValue,
	"--coverage":      isDenoCoverageValue,
	"--frozen":        isDenoFrozenValue,
	"--check":         isDenoCheckValue,
	"--no-check":      isDenoNoCheckValue,
	"--inspect":       isDenoInspectValue,
	"--inspect-brk":   isDenoInspectValue,
	"--inspect-wait":  isDenoInspectValue,
	"--watch":         isDenoWatchValue,
	"--watch-exclude": isDenoWatchValue,
	"--watch-hmr":     isDenoWatchValue,
	"--tunnel":        isDenoTunnelValue,
	"-t":              isDenoTunnelValue,
	"--lock":          isDenoLockValue,
	"--env-file":      isDenoEnvFileValue,
	"--install-alias": isDenoInstallAliasValue,
	"--allow-scripts": isDenoAllowScriptsValue,
	"--allow-import":  isDenoAllowImportValue,
	"-I":              isDenoAllowImportValue,
	"--allow-read":    isDenoAllowReadValue,
	"-R":              isDenoAllowReadValue,
	"--allow-net":     isDenoAllowNetValue,
	"-N":              isDenoAllowNetValue,
	"--allow-write":   isDenoAllowWriteValue,
	"-W":              isDenoAllowWriteValue,
	"--allow-env":     isDenoAllowEnvValue,
	"-E":              isDenoAllowEnvValue,
	"--allow-run":     isDenoAllowRunValue,
	"--allow-ffi":     isDenoAllowFFIValue,
	"--allow-sys":     isDenoAllowSysValue,
	"-S":              isDenoAllowSysValue,
	"--deny-read":     isDenoAllowReadValue,
	"--deny-write":    isDenoAllowWriteValue,
	"--deny-net":      isDenoAllowNetValue,
	"--deny-env":      isDenoAllowEnvValue,
	"--deny-run":      isDenoAllowRunValue,
	"--deny-ffi":      isDenoAllowFFIValue,
	"--deny-import":   isDenoAllowImportValue,
	"--deny-sys":      isDenoAllowSysValue,
}
