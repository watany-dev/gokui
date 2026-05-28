package safefs

// HasWindowsDrivePathPrefix reports whether path starts with a Windows drive
// designator such as "C:".
func HasWindowsDrivePathPrefix(path string) bool {
	if len(path) < 2 {
		return false
	}
	drive := path[0]
	if (drive < 'a' || drive > 'z') && (drive < 'A' || drive > 'Z') {
		return false
	}
	return path[1] == ':'
}
