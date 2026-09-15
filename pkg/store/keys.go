package store

const (
	pkPrefixProject = "PROJECT#"
	pkMidEnv        = "#ENV#"

	skPrefixConfig = "CONFIG#"
	skPrefixSecret = "SECRET#"
)

func pkFor(project, env string) string {
	return pkPrefixProject + project + pkMidEnv + env
}
