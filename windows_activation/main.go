//go:build windows

package main

import (
    "context"
    "flag"
    "fmt"
    "log"
    "sort"
    "strconv"
    "strings"

    "github.com/osquery/osquery-go"
    "github.com/osquery/osquery-go/plugin/table"
    "github.com/yusufpapurcu/wmi"
)

const windowsAppID = "55c92734-d682-4d71-983e-d6ec3f16059f"

type activationSnapshot struct {
    ProductDescription          string
    LicenseStatusCode           string
    GracePeriodRemainingMinutes string
    KMSConfiguredMachine        string
    KMSConfiguredPort           string
    QueryError                  string
}

type licensingProduct struct {
    Description                 *string
    LicenseStatus               *uint32
    GracePeriodRemaining        *uint32
    KeyManagementServiceMachine *string
    KeyManagementServicePort    *uint32
    PartialProductKey           *string
    LicenseIsAddon              *bool
}

type licensingService struct {
    KeyManagementServiceMachine *string
    KeyManagementServicePort    *uint32
}

func main() {
    socket := flag.String("socket", "", "osquery extension socket")
    timeout := flag.Int("timeout", 0, "osquery extension timeout")
    interval := flag.Int("interval", 0, "osquery extension interval")
    verbose := flag.Bool("verbose", false, "osquery extension verbose mode")
    version := flag.Bool("version", false, "show extension version")
    flag.Parse()
    _ = timeout
    _ = interval
    _ = verbose
    _ = version

    if *socket == "" {
        log.Fatal("missing --socket")
    }

    server, err := osquery.NewExtensionManagerServer("windows_activation_extension", *socket)
    if err != nil {
        log.Fatalf("create server failed: %v", err)
    }

    server.RegisterPlugin(table.NewPlugin(
        "windows_activation",
        columns(),
        generate,
    ))

    if err := server.Run(); err != nil {
        log.Fatalf("run server failed: %v", err)
    }
}

func columns() []table.ColumnDefinition {
    return []table.ColumnDefinition{
        table.TextColumn("product_description"),
        table.TextColumn("license_status_code"),
        table.TextColumn("license_status"),
        table.TextColumn("is_activated"),
        table.TextColumn("activation_channel"),
        table.TextColumn("grace_period_remaining_minutes"),
        table.TextColumn("kms_configured_machine"),
        table.TextColumn("kms_configured_port"),
        table.TextColumn("query_error"),
    }
}

func generate(_ context.Context, _ table.QueryContext) ([]map[string]string, error) {
    info := collectActivationInfo()
    return []map[string]string{info.Row()}, nil
}

func collectActivationInfo() activationSnapshot {
    product, err := queryPrimaryProduct()
    if err != nil {
        return activationSnapshot{QueryError: err.Error()}
    }

    snapshot := activationSnapshot{
        ProductDescription:          stringPtrValue(product.Description),
        LicenseStatusCode:           uint32Value(product.LicenseStatus, false, false),
        GracePeriodRemainingMinutes: uint32Value(product.GracePeriodRemaining, false, false),
        KMSConfiguredMachine:        stringPtrValue(product.KeyManagementServiceMachine),
        KMSConfiguredPort:           uint32Value(product.KeyManagementServicePort, true, true),
    }

    if snapshot.KMSConfiguredMachine == "" || snapshot.KMSConfiguredPort == "" {
        service, err := queryLicensingService()
        if err != nil {
            if snapshot.KMSConfiguredMachine == "" || snapshot.KMSConfiguredPort == "" {
                snapshot.QueryError = err.Error()
            }
            return snapshot
        }

        if snapshot.KMSConfiguredMachine == "" {
            snapshot.KMSConfiguredMachine = stringPtrValue(service.KeyManagementServiceMachine)
        }
        if snapshot.KMSConfiguredPort == "" {
            snapshot.KMSConfiguredPort = uint32Value(service.KeyManagementServicePort, true, true)
        }
    }

    return snapshot
}

func queryPrimaryProduct() (licensingProduct, error) {
    const query = "SELECT Description, LicenseStatus, GracePeriodRemaining, KeyManagementServiceMachine, KeyManagementServicePort, PartialProductKey, LicenseIsAddon FROM SoftwareLicensingProduct WHERE ApplicationID='" + windowsAppID + "'"

    var products []licensingProduct
    if err := wmi.QueryNamespace(query, &products, `root\cimv2`); err != nil {
        return licensingProduct{}, fmt.Errorf("query SoftwareLicensingProduct: %w", err)
    }
    if len(products) == 0 {
        return licensingProduct{}, fmt.Errorf("query SoftwareLicensingProduct: no rows for ApplicationID %s", windowsAppID)
    }

    sortProducts(products)
    return products[0], nil
}

func queryLicensingService() (licensingService, error) {
    const query = "SELECT KeyManagementServiceMachine, KeyManagementServicePort FROM SoftwareLicensingService"

    var rows []licensingService
    if err := wmi.QueryNamespace(query, &rows, `root\cimv2`); err != nil {
        return licensingService{}, fmt.Errorf("query SoftwareLicensingService: %w", err)
    }
    if len(rows) == 0 {
        return licensingService{}, fmt.Errorf("query SoftwareLicensingService: no rows")
    }

    return rows[0], nil
}

func sortProducts(products []licensingProduct) {
    sort.SliceStable(products, func(i, j int) bool {
        leftHasKey := stringPtrValue(products[i].PartialProductKey) != ""
        rightHasKey := stringPtrValue(products[j].PartialProductKey) != ""
        if leftHasKey != rightHasKey {
            return leftHasKey
        }

        leftAddon := boolPtrValue(products[i].LicenseIsAddon)
        rightAddon := boolPtrValue(products[j].LicenseIsAddon)
        if leftAddon != rightAddon {
            return !leftAddon
        }

        leftStatus := uint32PtrInt(products[i].LicenseStatus)
        rightStatus := uint32PtrInt(products[j].LicenseStatus)
        if leftStatus != rightStatus {
            return leftStatus > rightStatus
        }

        return stringPtrValue(products[i].Description) < stringPtrValue(products[j].Description)
    })
}

func (a activationSnapshot) Row() map[string]string {
    statusCode := atoi(a.LicenseStatusCode)

    return map[string]string{
        "product_description":            a.ProductDescription,
        "license_status_code":            a.LicenseStatusCode,
        "license_status":                 licenseStatusText(statusCode),
        "is_activated":                   boolString(statusCode == 1),
        "activation_channel":             detectActivationChannel(a.ProductDescription, a.KMSConfiguredMachine),
        "grace_period_remaining_minutes": sanitizeNumericString(a.GracePeriodRemainingMinutes, false),
        "kms_configured_machine":         a.KMSConfiguredMachine,
        "kms_configured_port":            sanitizeNumericString(a.KMSConfiguredPort, true),
        "query_error":                    a.QueryError,
    }
}

func atoi(v string) int {
    n, _ := strconv.Atoi(strings.TrimSpace(v))
    return n
}

func boolString(v bool) string {
    if v {
        return "true"
    }
    return "false"
}

func boolPtrValue(v *bool) bool {
    return v != nil && *v
}

func sanitizeNumericString(value string, zeroIsEmpty bool) string {
    value = strings.TrimSpace(value)
    switch value {
    case "":
        return ""
    case "4294967295":
        return ""
    case "0":
        if zeroIsEmpty {
            return ""
        }
    }
    return value
}

func stringPtrValue(v *string) string {
    if v == nil {
        return ""
    }
    return strings.TrimSpace(*v)
}

func uint32PtrInt(v *uint32) int {
    if v == nil {
        return 0
    }
    return int(*v)
}

func uint32Value(v *uint32, zeroIsEmpty, maxUintIsEmpty bool) string {
    if v == nil {
        return ""
    }
    if zeroIsEmpty && *v == 0 {
        return ""
    }
    if maxUintIsEmpty && *v == ^uint32(0) {
        return ""
    }
    return strconv.FormatUint(uint64(*v), 10)
}

func licenseStatusText(code int) string {
    switch code {
    case 0:
        return "Unlicensed"
    case 1:
        return "Licensed"
    case 2:
        return "OOBGrace"
    case 3:
        return "OOTGrace"
    case 4:
        return "NonGenuineGrace"
    case 5:
        return "Notification"
    case 6:
        return "ExtendedGrace"
    default:
        return "Unknown"
    }
}

func detectActivationChannel(description, kmsMachine string) string {
    upperDescription := strings.ToUpper(description)
    switch {
    case strings.Contains(upperDescription, "VOLUME_KMSCLIENT"):
        return "kms_client"
    case strings.Contains(upperDescription, "VOLUME_MAK"):
        return "mak"
    case strings.Contains(upperDescription, "RETAIL"):
        return "retail"
    case strings.Contains(upperDescription, "OEM"):
        return "oem"
    case strings.Contains(upperDescription, "ADBA") || strings.Contains(upperDescription, "ACTIVE_DIRECTORY"):
        return "adba"
    case kmsMachine != "":
        return "kms"
    default:
        return "unknown"
    }
}
