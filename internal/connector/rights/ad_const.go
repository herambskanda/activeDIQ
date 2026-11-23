package rights

// searchFlagConfidential is fCONFIDENTIAL (searchFlags bit 7): reading the attribute needs
// CONTROL_ACCESS as well as READ_PROPERTY.
const searchFlagConfidential = 0x80
