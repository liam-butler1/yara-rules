rule jar_file_with_carLambo_main_class
{
    meta:
        description = "Detects a .jar file with the main class carLambo.main as seen in JRAT Malware Samples"
        author = "Liam Butler"
        reference = "https://www.virustotal.com/gui/search/similar-to%253Abb89acbea16bc8318aea9275e037b203252ffba8cab52ef017f338bed20062fb/files"

    strings:
        $main_class = "carLambo.main"

    condition:
        $main_class in (java_class_names) and $main_class at entrypoint
}
