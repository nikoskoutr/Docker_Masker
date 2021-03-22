import qbs

DynamicLibrary {
    name: "masker"
    Depends { name: "cpp" }
    Depends { name: "InternalApi" }

    cpp.includePaths: ["../include"]
    cpp.dynamicLibraries: ["polarssl"]

    destinationDirectory: './TAs'
    cpp.defines: ["TA_PLUGIN"]

    files: [
        "TrustedApplication.c",
        "../include/tee_ta_properties.h",
    ]
}
