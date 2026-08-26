package package_manager

type PackageManager interface {
	Name() string
	Install(args []string) error
}
