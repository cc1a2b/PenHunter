package utils

// Color constants matching penhunter.sh exactly
const (
	NC        = "\033[0m"    // Reset/No Color (same as Reset)
	Reset     = "\033[0m"    // Reset/No Color
	Red       = "\033[0;31m" // RED
	Green     = "\033[0;32m" // GREEN
	Yellow    = "\033[0;33m" // YELLOW
	Blue      = "\033[0;34m" // BLUE
	Cyan      = "\033[0;36m" // CYAN
	Purple    = "\033[0;35m" // PURPLE
	Magenta   = "\033[0;35m" // MAGENTA (same as Purple)
	Gray      = "\033[0;37m" // GRAY
	Brown     = "\033[0;33m" // BROWN (same as Yellow)
	DarkGreen = "\033[38;5;22m" // DARK_GREEN
)

func Colorize(text, color string) string {
	return color + text + NC
}
