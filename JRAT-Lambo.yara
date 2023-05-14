rule jar_file_with_carLambo_main_class
{
    meta:
        description = "Detects a .jar file with the main class carLambo.main as seen in JRAT Malware Samples"
        author = "Liam Butler"

    strings:
        $main_class = "carLambo.main"

    condition:
        $main_class in (java_class_names) and $main_class at entrypoint
}
