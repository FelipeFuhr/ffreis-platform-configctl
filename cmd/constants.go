package cmd

const (
	flagProject = "project"
	flagEnv     = "env"
	flagAs      = "as"
	flagOut     = "out"

	keyProject = "project"
	keyValue   = "value"

	formatJSON = "json"

	checksumFormatSHA256 = "sha256:%x"

	// envNoReveal is the fleet-wide kill switch: when set to a truthy value
	// (see isEnvTruthy), 'secret get --reveal' refuses to decrypt/print the
	// plaintext regardless of the flag. It exists so a secret value can never
	// be printed to a stream that lands in an AI agent's session transcript —
	// 'secret exec' and 'secret export-env' are the supported alternatives,
	// since neither ever writes the plaintext to a stream configctl controls.
	envNoReveal = "CONFIGCTL_NO_REVEAL"
)
