static const uint8_t orig_cert[] =
{
0x30, 0x82, 0x02, 0x37, 0x30, 0x82, 0x01, 0xDE, 0xA0, 0x03,
0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0x82, 0x1E, 0x6D, 0xD3,
0xA9, 0x9B, 0x01, 0x70, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86,
0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x81, 0x86, 0x31,
0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
0x4B, 0x52, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04,
0x08, 0x0C, 0x05, 0x53, 0x65, 0x6F, 0x75, 0x6C, 0x31, 0x0E,
0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x05, 0x53,
0x65, 0x6F, 0x75, 0x6C, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
0x55, 0x04, 0x0A, 0x0C, 0x0A, 0x41, 0x6C, 0x69, 0x63, 0x65,
0x20, 0x49, 0x6E, 0x63, 0x2E, 0x31, 0x0E, 0x30, 0x0C, 0x06,
0x03, 0x55, 0x04, 0x0B, 0x0C, 0x05, 0x41, 0x6C, 0x69, 0x63,
0x65, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03,
0x0C, 0x0C, 0x63, 0x61, 0x2E, 0x61, 0x6C, 0x69, 0x63, 0x65,
0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x09,
0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16,
0x0C, 0x63, 0x61, 0x40, 0x61, 0x6C, 0x69, 0x63, 0x65, 0x2E,
0x63, 0x6F, 0x6D, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x38, 0x31,
0x30, 0x31, 0x31, 0x31, 0x30, 0x32, 0x32, 0x30, 0x36, 0x5A,
0x17, 0x0D, 0x31, 0x39, 0x31, 0x30, 0x31, 0x31, 0x31, 0x30,
0x32, 0x32, 0x30, 0x36, 0x5A, 0x30, 0x81, 0x86, 0x31, 0x0B,
0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4B,
0x52, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x08,
0x0C, 0x05, 0x53, 0x65, 0x6F, 0x75, 0x6C, 0x31, 0x0E, 0x30,
0x0C, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x05, 0x53, 0x65,
0x6F, 0x75, 0x6C, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55,
0x04, 0x0A, 0x0C, 0x0C, 0x53, 0x4E, 0x55, 0x20, 0x42, 0x6F,
0x62, 0x20, 0x4C, 0x74, 0x64, 0x2E, 0x31, 0x10, 0x30, 0x0E,
0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x07, 0x53, 0x4E, 0x55,
0x20, 0x42, 0x6F, 0x62, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03,
0x55, 0x04, 0x03, 0x0C, 0x09, 0x2A, 0x2E, 0x62, 0x6F, 0x62,
0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x09,
0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16,
0x0B, 0x62, 0x6F, 0x62, 0x40, 0x62, 0x6F, 0x62, 0x2E, 0x63,
0x6F, 0x6D, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48,
0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x45,
0xF7, 0x2A, 0xE1, 0xFF, 0xED, 0x67, 0x65, 0x80, 0x22, 0x30,
0x85, 0x3A, 0xC2, 0x66, 0x6A, 0x83, 0x83, 0x30, 0x4C, 0x1D,
0xFD, 0x47, 0x29, 0xB7, 0xC8, 0x59, 0xCA, 0x52, 0xCC, 0x05,
0x50, 0x3C, 0x8E, 0xC1, 0xA6, 0x1C, 0x9C, 0x7F, 0x00, 0xCB,
0x25, 0xDE, 0xCC, 0xCB, 0x08, 0x38, 0xE6, 0x67, 0xB3, 0x76,
0x05, 0x5D, 0x5C, 0xAD, 0x23, 0xB3, 0x4F, 0x91, 0xC5, 0x5F,
0x24, 0xAA, 0xED, 0xA3, 0x33, 0x30, 0x31, 0x30, 0x09, 0x06,
0x03, 0x55, 0x1D, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0B,
0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x07,
0x80, 0x30, 0x17, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x10,
0x30, 0x0E, 0x82, 0x0C, 0x2A, 0x2E, 0x6F, 0x72, 0x69, 0x67,
0x69, 0x6E, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x0A, 0x06, 0x08,
0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x47,
0x00, 0x30, 0x44, 0x02, 0x20, 0x77, 0x89, 0xAD, 0x0D, 0x7F,
0xBA, 0x08, 0xD2, 0x13, 0x92, 0xFE, 0xA0, 0x4F, 0x78, 0x04,
0x3A, 0x89, 0x35, 0x59, 0x6A, 0x04, 0x77, 0x91, 0xD6, 0x56,
0x23, 0xC7, 0xCD, 0x8C, 0x47, 0x58, 0xF2, 0x02, 0x20, 0x2F,
0x88, 0x86, 0x05, 0xAF, 0x7B, 0x63, 0x2A, 0xA1, 0x0F, 0xB3,
0xF7, 0xB8, 0xD0, 0x1C, 0xA9, 0x34, 0x44, 0xF4, 0x55, 0x23,
0x01, 0x71, 0xCC, 0xA4, 0x6D, 0xE5, 0x57, 0xB6, 0x88, 0x55,
0xC9
};
