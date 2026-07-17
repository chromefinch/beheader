rule PCI_Credit_Card {
    meta:
        author = "Antigravity"
        description = "Detects potential Credit Card numbers (PCI)"
        date = "2026-07-16"
    strings:
        $cc_visa = /4[0-9]{12}([0-9]{3})?/
        $cc_master = /5[1-5][0-9]{14}/
        $cc_amex = /3[47][0-9]{13}/
        $cc_diners = /3(0[0-5]|[68][0-9])[0-9]{11}/
        $cc_discover = /6(011|5[0-9]{2})[0-9]{12}/
        $cc_jcb = /(2131|1800|35[0-9]{3})[0-9]{11}/
    condition:
        any of them
}
