import os
import re
import stat
import requests
import argparse
import time
from uuid import uuid4
from packageurl import PackageURL
from collections import defaultdict

from cyclonedx.builder.this import this_component as cdx_lib_component
from cyclonedx.exception import MissingOptionalDependencyException
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model import XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.output import make_outputter
from cyclonedx.output.json import JsonV1Dot5
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation import make_schemabased_validator
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.model.vulnerability import Vulnerability, VulnerabilityRating, VulnerabilityScoreSource


def parse_module(mod_str, module_names):
    """
    Parse a module string to find the longest valid module name from a set of known module names.

    Args:
        mod_str (str): The module string to parse
        module_names (set): Set of valid module names

    Returns:
        str: The longest valid module name found in the string, or None if no match found
    """
    mod_lst = mod_str.split('-')
    if mod_lst[-1] in module_names:
        return mod_lst[-1]
    else:
        for i in range(len(mod_lst)):
            if '-'.join(mod_lst[i:]) in module_names:
                return '-'.join(mod_lst[i:])


def parse_makefile_def(file_path):
    """
    Parse Makefile.def and extract explicitly declared dependencies.

    Args:
        file_path (str): Path to the Makefile.def file

    Returns:
        dict: Dictionary with module names as keys and their direct dependencies as values
    """
    dependencies = defaultdict(list)
    module_names = set()

    with open(file_path, 'r') as f:
        content = f.read()
        # Extract module names
        for match in re.finditer(
            r'(?:host_modules|target_modules)\s*=\s*{\s*module\s*=\s*([^;]+)',
            content
        ):
            module = match.group(1).strip()
            module_names.add(module)

        # Extract dependencies
        for match in re.finditer(
            r'dependencies\s*=\s*{\s*module\s*=\s*([^;]+);\s*on\s*=\s*([^;]+);',
            content
        ):
            module_raw = match.group(1).strip()
            module = parse_module(module_raw, module_names)
            dep_raw = match.group(2).strip()
            dep = parse_module(dep_raw, module_names)
            if module in module_names and dep in module_names:
                if dep not in dependencies[module]:
                    dependencies[module].append(dep)
    return dict(dependencies)


def add_dependencies(comp_refs, bom, root_dir):
    """
    Add dependencies between components to the BOM based on Makefile.def.

    Args:
        comp_refs (dict): Dictionary of component references
        bom (Bom): The Bill of Materials object
        root_dir (str): Root directory containing Makefile.def
    """
    dep_dict = parse_makefile_def(root_dir + "/Makefile.def")
    for comp_name in dep_dict:
        if comp_name in comp_refs.keys():
            component = comp_refs[comp_name]
            component_lst = []
            for dep_name in dep_dict[comp_name]:
                if dep_name in comp_refs.keys():
                    bom.register_dependency(comp_refs[dep_name], [component])

def send_nvd_request(vendor, package_name, version):
    """
    Search for CVEs in the NVD database for a specific package.

    Args:
        vendor (str): Vendor name
        package_name (str): Package name
        version (str): Package version

    Returns:
        list: List of dictionaries containing CVE details, or None if no CVEs found
    """
    time.sleep(10)  # Rate limiting
    cves = []
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "cpeName": "cpe:2.3:a:{0}:{1}:{2}:*:*:*:*:*:*:*".format(
            vendor, package_name, version
        )
    }
    response = requests.get(url, params=params)

    if response.status_code == 200:
        data = response.json()
        for vulnerability in data.get("vulnerabilities", []):
            cve_info = vulnerability.get("cve", {})
            cve_id = cve_info.get("id")
            cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            metrics = cve_info.get("metrics", {})
            cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore")
            cvss_v3 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}).get("baseScore")

            if cve_id:
                cves.append({
                    "CVE_ID": cve_id,
                    "URL": cve_url,
                    "SCORES": [
                        [VulnerabilityScoreSource.CVSS_V2, cvss_v2],
                        [VulnerabilityScoreSource.CVSS_V3, cvss_v3],
                    ]
                })

    return cves if cves else None


def search_nvd(package_name, version):
    """
    Search for CVEs in the NVD database for a given package name and version.
    Tries common vendor names if the first attempt fails.

    Args:
        package_name (str): Package name to search
        version (str): Package version

    Returns:
        list: List of CVEs found, or empty list if none found
    """
    cves = send_nvd_request("gnu", package_name, version)
    if cves:
        return cves
    else:
        cves = send_nvd_request(package_name, package_name, version)
        if cves:
            return cves
    return []


def is_utility_by_content(file_path):
    """
    Check if a file is a utility script by examining its first line for shebang.

    Args:
        file_path (str): Path to the file

    Returns:
        bool: True if file starts with shebang, False otherwise
    """
    try:
        with open(file_path, 'r') as file:
            first_line = file.readline()
            return first_line.startswith('#!')
    except Exception:
        return False


def is_executable(file_path):
    """
    Check if a file is executable.

    Args:
        file_path (str): Path to the file

    Returns:
        bool: True if file is executable, False otherwise
    """
    return os.access(file_path, os.X_OK)


def is_utility_by_extension(file_path):
    """
    Check if a file is a utility script by its extension.

    Args:
        file_path (str): Path to the file

    Returns:
        bool: True if file has a known script extension, False otherwise
    """
    utility_extensions = {'.sh', '.bat', '.cmd', '.pl', '.rb'}
    _, ext = os.path.splitext(file_path)
    return ext.lower() in utility_extensions


def is_utility(file_path):
    """
    Determine if a file is a utility script by either extension or content.

    Args:
        file_path (str): Path to the file

    Returns:
        bool: True if file is a utility script, False otherwise
    """
    return (is_utility_by_extension(file_path) or
            is_utility_by_content(file_path))


def add_gcc_to_bom(bom):
    """
    Add GCC component to the BOM with its vulnerabilities.

    Args:
        bom (Bom): The Bill of Materials object

    Returns:
        Component: The created GCC component
    """
    bom_ref = str(uuid4())
    component = Component(
        type=ComponentType.APPLICATION,
        name="gcc",
        version="4.1.1",
        bom_ref=bom_ref
    )
    bom.components.add(component)
    cves = search_nvd("gcc", "4.1.1")
    for vuln in cves:
        rating = []
        for scr in vuln["SCORES"]:
            rating.append(VulnerabilityRating(score=scr[1], method=scr[0]))
        vulnerability = Vulnerability(
            bom_ref=bom_ref,
            id=vuln["CVE_ID"],
            source=vuln["URL"],
            ratings=set(rating)
        )
        bom.vulnerabilities.add(vulnerability)
    return component


def add_library_to_bom(bom, package_name, name_from_path, ver_parsed):
    """
    Add a library component to the BOM with its vulnerabilities.

    Args:
        bom (Bom): The Bill of Materials object
        package_name (str): Official package name
        name_from_path (str): Name derived from file path
        ver_parsed (str): Parsed version string

    Returns:
        Component: The created library component
    """
    bom_ref = str(uuid4())
    component = Component(
        type=ComponentType.LIBRARY,
        name=package_name if package_name not in ("", 'package-unused') else name_from_path,
        version=ver_parsed if ver_parsed not in (' ', "version-unused") else "not_found",
        bom_ref=bom_ref
    )
    bom.components.add(component)

    if "GNU" in package_name:
        package_name = name_from_path
    if package_name == "package-unused":
        package_name = name_from_path

    cves = search_nvd(package_name, ver_parsed)
    for vuln in cves:
        rating = []
        for scr in vuln["SCORES"]:
            rating.append(VulnerabilityRating(score=scr[1], method=scr[0]))
        vulnerability = Vulnerability(
            bom_ref=bom_ref,
            id=vuln["CVE_ID"],
            source=vuln["URL"],
            ratings=set(rating)
        )
        bom.vulnerabilities.add(vulnerability)
    return component


def add_forbidden_to_bom(bom, comp_refs, libraries_pathes):
    """
    Add forbidden libraries to the BOM with their vulnerabilities.

    Args:
        bom (Bom): The Bill of Materials object
        comp_refs (dict): Dictionary to store component references
        libraries_pathes (set): Set to store library paths
    """
    component = add_library_to_bom(bom, "libiberty", "", "not_found")
    comp_refs["libiberty"] = component
    libraries_pathes.add("libiberty")

    component = add_library_to_bom(bom, "libintl", "", "0.12.1")
    comp_refs["intl"] = component
    libraries_pathes.add("intl")

    component = add_library_to_bom(bom, "zlib", "", "1.2.3")
    comp_refs["zlib"] = component
    libraries_pathes.add("zlib")

    component = add_library_to_bom(bom, "boehm-gc", "", "not_found")
    comp_refs["boehm-gc"] = component
    libraries_pathes.add("boehm-gc")

    component = add_library_to_bom(bom, "fastjar", "", "0.90")
    comp_refs["fastjar"] = component
    libraries_pathes.add("fastjar")

    component = add_gcc_to_bom(bom)
    comp_refs["gcc"] = component
    libraries_pathes.add("gcc")


def scan_directory(path):
    """
    Scan a directory and generate a Software Bill of Materials (SBOM).

    Args:
        path (str): Path to the directory to scan
    """
    bom = Bom()
    bom.metadata.tools.components.add(cdx_lib_component())
    bom.metadata.tools.components.add(Component(
        name='sbom-generator',
        type=ComponentType.APPLICATION,
    ))

    if not os.path.exists(path):
        print(f"Path {path} does not exist.")
        return

    executables = list()
    libraries_pathes = set()
    comp_refs = dict()

    for root, dirs, files in os.walk(path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                flag = False
                name = str()
                tar_name = str()

                if is_utility(file_path):
                    executables.append(file_path)

                with open(file_path, 'r', encoding='utf-8') as file:
                    for line_number, line in enumerate(file, start=1):
                        if "PACKAGE_NAME='" in line:
                            flag = True
                            package_name = line.strip().split("'")[1]
                        if "PACKAGE_TARNAME='" in line:
                            tar_name = line.strip().split("'")[1]
                        if "PACKAGE_VERSION='" in line:
                            ver_parsed = line.strip().split("'")[1]
                            if flag:
                                name_from_path = file_path.split('/')[2]
                                if "x86_64-unknown-linux-gnu" not in name_from_path:
                                    if name_from_path == "libgfortran":
                                        ver_parsed = "4." + ver_parsed[2:]
                                    component = add_library_to_bom(
                                        bom, package_name, name_from_path, ver_parsed
                                    )
                                    if tar_name and package_name != "package-unused" and tar_name != "cpplib":
                                        comp_refs[tar_name] = component
                                    else:
                                        comp_refs[name_from_path] = component
                                    libraries_pathes.add(name_from_path)
            except (UnicodeDecodeError, PermissionError):
                continue

    add_forbidden_to_bom(bom, comp_refs, libraries_pathes)
    add_dependencies(comp_refs, bom, path)

    for i in executables:
        if (i.split('/')[2] not in libraries_pathes) and ("x86_64-unknown-linux-gnu" not in i):
            ver_parsed = str()
            package_name = i.split('/')[-1]
            try:
                with open(i, 'r', encoding='utf-8') as file:
                    for line_number, line in enumerate(file, start=1):
                        if "scriptversion" in line:
                            ver_parsed = line.strip().split('=')[1]
                            break
            except (UnicodeDecodeError, PermissionError):
                pass

            component = Component(
                type=ComponentType.FILE,
                name=package_name,
                version=ver_parsed,
                mime_type="executable"
            )
            bom.components.add(component)

    my_json_outputter = JsonV1Dot5(bom)
    serialized_json = my_json_outputter.output_as_string(indent=2)
    print(serialized_json)
    my_json_validator = JsonStrictValidator(SchemaVersion.V1_6)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a cyclonedx sbom file for gcc 4.1.1 based on its source code"
    )
    parser.add_argument("--dir", required=True,
                            help="Root directory of the project.")
    args = parser.parse_args()
    components = scan_directory(args.dir)
