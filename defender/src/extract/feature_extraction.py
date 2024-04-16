import pefile

def extract_features(data):
    """
    Extract features from the given binary data (a byte string).

    :param data: The binary data from which to extract features.
    :return: A list of feature values.
    """
    pe = pefile.PE(data=data)

    # Extract features from the PE file
    features = {}
    features["Machine"] = pe.FILE_HEADER.Machine
    features["NumberOfSections"] = pe.FILE_HEADER.NumberOfSections
    features["TimeDateStamp"] = pe.FILE_HEADER.TimeDateStamp
    features["PointerToSymbolTable"] = pe.FILE_HEADER.PointerToSymbolTable
    features["NumberOfSymbols"] = pe.FILE_HEADER.NumberOfSymbols
    features["SizeOfOptionalHeader"] = pe.FILE_HEADER.SizeOfOptionalHeader
    features["Characteristics"] = pe.FILE_HEADER.Characteristics
    features["Magic"] = pe.OPTIONAL_HEADER.Magic
    features["MajorLinkerVersion"] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    features["MinorLinkerVersion"] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    features["SizeOfCode"] = pe.OPTIONAL_HEADER.SizeOfCode
    features["SizeOfInitializedData"] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    features["SizeOfUninitializedData"] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    features["AddressOfEntryPoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    features["BaseOfCode"] = pe.OPTIONAL_HEADER.BaseOfCode
    features["ImageBase"] = pe.OPTIONAL_HEADER.ImageBase
    features["SectionAlignment"] = pe.OPTIONAL_HEADER.SectionAlignment
    features["FileAlignment"] = pe.OPTIONAL_HEADER.FileAlignment
    features["MajorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    features["MinorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    features["MajorImageVersion"] = pe.OPTIONAL_HEADER.MajorImageVersion
    features["MinorImageVersion"] = pe.OPTIONAL_HEADER.MinorImageVersion
    features["MajorSubsystemVersion"] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    features["MinorSubsystemVersion"] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    features["SizeOfImage"] = pe.OPTIONAL_HEADER.SizeOfImage
    features["SizeOfHeaders"] = pe.OPTIONAL_HEADER.SizeOfHeaders
    features["CheckSum"] = pe.OPTIONAL_HEADER.CheckSum
    features["Subsystem"] = pe.OPTIONAL_HEADER.Subsystem
    features["DllCharacteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
    features["SizeOfStackReserve"] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    features["SizeOfStackCommit"] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    features["SizeOfHeapReserve"] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    features["SizeOfHeapCommit"] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    features["LoaderFlags"] = pe.OPTIONAL_HEADER.LoaderFlags
    features["NumberOfRvaAndSizes"] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    return features, list(pe.header)

    