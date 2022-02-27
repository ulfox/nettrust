package firewall

var (
	errFWDHook                string = "not supported firewall hook [%s]"
	errNotSupportedFWDBackend string = "[%s] is not yet supported"
	errUnknownFWDBackend      string = "not supported firewall backend [%s]"
	errEmptyName              string = "%s name not allowed to be empty"
	infoFWDCreate             string = "creating [%s] rules"
	infoFWDInput              string = "creating input rules"
)
