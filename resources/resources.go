package resources

import _ "embed"

// IOCPackagesCustomCSV contains the repository-maintained custom npm IOC feed.
//
//go:embed ioc-packages-custom.csv
var IOCPackagesCustomCSV []byte
