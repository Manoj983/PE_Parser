import pefile
import array
import os
import math
import hashlib
#import array
#import sys
#import argparse
#file_path = pefile.PE("/home/akakrazy/PWK/malware_analysis/trojanshtt10.exe")
file_path = "/home/akakrazy/PWK/malware_analysis/eula.exe"
pe = pefile.PE(file_path)
#pe.result.append_info()
#   HEADER  


#IMAGE_RESOURCE_DIRECTORY table
def get_entropy(data):
    if len(data) == 0:
	    return 0.0
    occurences = array.array('L', [0]*256)
    for x in data:
  	    occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0#Shannon entropy of file
    for x in occurences:
	    if x:
	        p_x = float(x) / len(data)
	        entropy -= p_x*math.log(p_x, 2)

    return entropy

def get_resources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):# hasattr(object, attribute) The hasattr() function returns True if the specified object has the specified attribute, otherwise False.
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources




def get_version_info(pe): #error in this section
    """Return version infos"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
          res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
          res['os'] = pe.VS_FIXEDFILEINFO.FileOS
          res['type'] = pe.VS_FIXEDFILEINFO.FileType
          res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
          res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
          res['signature'] = pe.VS_FIXEDFILEINFO.Signature
          res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return result
file_ = file_path
with open(file_,"rb") as f:
    bytes = f.read()
    md5_returned = hashlib.md5(bytes).hexdigest()
    #result.append(md5_returned)

def extract_infos(file_path):
    result = []
    #file_path = "/home/akakrazy/PWK/malware_analysis/trojanshtt10.exe"
    pe =pefile.PE(file_path)
    result.append(os.path.basename(file_path)) #to print the name of the file only
    result.append(md5_returned)
    #[IMAGE_FILE_HEADER]
    result.append(pe.FILE_HEADER.Machine)
    result.append(pe.FILE_HEADER.SizeOfOptionalHeader)
    result.append(pe.FILE_HEADER.Characteristics)
    #[OPTIONAL_HEADER]
    result.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
    result.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)
    result.append(pe.OPTIONAL_HEADER.SizeOfCode)
    result.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
    result.append( pe.OPTIONAL_HEADER.SizeOfUninitializedData)
    result.append( pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    result.append(pe.OPTIONAL_HEADER.BaseOfCode)
    result.append(pe.OPTIONAL_HEADER.BaseOfData)
    result.append(pe.OPTIONAL_HEADER.ImageBase)
    result.append(pe.OPTIONAL_HEADER.SectionAlignment)
    result.append( pe.OPTIONAL_HEADER.FileAlignment)
    result.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    result.append(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
    result.append(pe.OPTIONAL_HEADER.MajorImageVersion)
    result.append(pe.OPTIONAL_HEADER.MinorImageVersion)
    result.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
    result.append(pe.OPTIONAL_HEADER.MinorSubsystemVersion)
    result.append(pe.OPTIONAL_HEADER.SizeOfImage)
    result.append(pe.OPTIONAL_HEADER.SizeOfHeaders)
    result.append(pe.OPTIONAL_HEADER.CheckSum)
    result.append(pe.OPTIONAL_HEADER.Subsystem)
    result.append(pe.OPTIONAL_HEADER.DllCharacteristics)
    result.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)
    result.append(pe.OPTIONAL_HEADER.SizeOfStackCommit)
    result.append(pe.OPTIONAL_HEADER.SizeOfHeapReserve)
    result.append(pe.OPTIONAL_HEADER.SizeOfHeapCommit)
    result.append(pe.OPTIONAL_HEADER.LoaderFlags)
    result.append(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)

    #SECTIONS
    #[SECTION_HEADER]
    result.append(len(pe.sections))
    entropy = list(map(lambda x:x.get_entropy(), pe.sections)) #TypeError: object of type 'map' has no len() 
    #result.append(pe.sections)
    #x=lambda a :a*10
    #result.append(x(5)) -->50
    #result.append(entropy)
    #result.append(len(entropy))
    result.append(sum(entropy)/float(len(entropy)))
    result.append(min(entropy))
    result.append(max(entropy))

    raw_sizes = list(map(lambda x:x.SizeOfRawData, pe.sections))
    result.append(sum(raw_sizes)/float(len(raw_sizes)))
    result.append(min(raw_sizes))
    result.append(max(raw_sizes))
    virtual_sizes = list(map(lambda x:x.Misc_VirtualSize, pe.sections))
    result.append(sum(virtual_sizes)/float(len(virtual_sizes)))
    result.append(min(virtual_sizes))
    result.append(max(virtual_sizes))
    #result.append("SectionsMeanEntropy:" +pe.SECTION_HEADER.Entropy)))

    #IMPORT
    #[DIRECTORY_ENTRY_IMPORT]
    #result.append(pe.IMAGE_DIRECTORY_ENTRY_IMPORT)
    result.append(len(pe.DIRECTORY_ENTRY_IMPORT))
    imports = list(sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])) #list optional
    result.append(len(imports))
    result.append(len(list(filter(lambda x:x.name is None, imports))))
    #result.append("SectionsMeanEntropy:" + pe.SECTION_HEADER.Entropy)))
    #SECTION NEED TO CONTINUE

    #result.append("Sectionss:"+ hex(pe.sections.VirtualAddress))
    #EXPORT
    # [DIRECTORY_ENTRY_EXPORT] 
    try:
        result.append(len(pe.DIRECTORY_ENTRY_EXPORT))
    except AttributeError:
            result.append("0")



    resources= get_resources(pe)
    result.append(len(resources))
    if len(resources)> 0:
        entropy = list(map(lambda x:x[0], resources))
        result.append(sum(entropy)/float(len(entropy)))
        result.append(min(entropy))
        result.append(max(entropy))
        sizes = list(map(lambda x:x[1], resources))
        result.append(sum(sizes)/float(len(sizes)))
        result.append(min(sizes))
        result.append(max(sizes))
    else:
        result.append("0")
        result.append("0")
        result.append("0")
        result.append("0")
        result.append("0")
        result.append("0")

    #for LoadconfigurationSize
    try:
        result.append(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size)
    except AttributeError:
        result.append("0")

    #for versionSize
    '''
    version_infos = get_version_info(pe)
    result.append(type(version_infos))
    result.append(len(version_infos.keys()))
    '''
    try:
        version_infos = get_version_info(pe)
        result.append(type(version_infos))
        result.append(len(version_infos.keys()))
    except AttributeError:
        result.append("0")
    return result
#print(res)
if __name__=='__main__':
    output_csv = "data_csv.csv"
    csv_seperator = "|"
    columns = ["Name",
        "md5",
        "Machine",
        "SizeOfOptionalHeader",
        "Characteristics",
        "MajorLinkerVersion",
        "MinorLinkerVersion",
        "SizeOfCode",
        "SizeOfInitializedData",
        "SizeOfUninitializedData",
        "AddressOfEntryPoint",
        "BaseOfCode",
        "BaseOfData",
        "ImageBase",
        "SectionAlignment",
        "FileAlignment",
        "MajorOperatingSystemVersion",
        "MinorOperatingSystemVersion",
        "MajorImageVersion",
        "MinorImageVersion",
        "MajorSubsystemVersion",
        "MinorSubsystemVersion",
        "SizeOfImage",
        "SizeOfHeaders",
        "CheckSum",
        "Subsystem",
        "DllCharacteristics",
        "SizeOfStackReserve",
        "SizeOfStackCommit",
        "SizeOfHeapReserve",
        "SizeOfHeapCommit",
        "LoaderFlags",
        "NumberOfRvaAndSizes",
        "SectionsNb",
        "SectionsMeanEntropy",
        "SectionsMinEntropy",
        "SectionsMaxEntropy",
        "SectionsMeanRawsize",
        "SectionsMinRawsize",
        "SectionMaxRawsize",
        "SectionsMeanVirtualsize",
        "SectionsMinVirtualsize",
        "SectionMaxVirtualsize",
        "ImportsNbDLL",
        "ImportsNb",
        "ImportsNbOrdinal",
        "ExportNb",
        "ResourcesNb",
        "ResourcesMeanEntropy",
        "ResourcesMinEntropy",
        "ResourcesMaxEntropy",
        "ResourcesMeanSize",
        "ResourcesMinSize",
        "ResourcesMaxSize",
        "LoadConfigurationSize",
        "VersionInformationSize",
        "legitimate"

    ]
    file_= open(output_csv,"a")
    file_.write(csv_seperator.join(columns)+"\n")
    ffile = file_path
    print(ffile)
    result = extract_infos(os.path.join(ffile))
    result.append("1")
    #result.append("0")
    file_.write(csv_seperator.join(map(lambda x:str(x), result)) + "\n")
    
    
    file_.close()

