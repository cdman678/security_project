import pandas as pd
import numpy as np
import hashlib
import array
import math
import pefile


class FeatureExtractor:

    def __init__(self, path):
        self.path = path
        self.characteristics = list()

    def getFileFeatures(self):
        ###
        # Opens and reads file from users provided path.
        # Ultimately close file after reading characteristics
        ###
        try:
            fileData = open(self.path, mode='rb')
            peData = pefile.PE(self.path)
            self.getCharacteristics(peData, fileData)

        finally:
            fileData.close()

        df = pd.DataFrame(self.characteristics)  # to df
        dfT = df.T  # transpose
        dfT = dfT.rename(columns=dfT.iloc[0]).drop(dfT.index[0])  # drop top row and make labels headers
        return dfT

    def get_resources(self, pe):
        ###
        # Helper function to iterate and get resource entroy and sizes if they exist.
        ###

        """Extract resources :
        [entropy, size]"""
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                       resource_lang.data.struct.Size)
                                    size = resource_lang.data.struct.Size
                                    entropy = self.get_entropy(data)

                                    resources.append([entropy, size])
            except Exception as e:
                return resources
        return resources

    def get_entropy(self, data):
        ###
        # Helper function to calculate entroy.
        ###

        if len(data) == 0:
            return 0.0
        occurences = array.array('L', [0] * 256)
        for x in data:
            occurences[x if isinstance(x, int) else ord(x)] += 1
        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x * math.log(p_x, 2)
        return entropy

    def get_version_info(self, pe):
        ###
        # Helper function to fetch version info
        ###
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
        return res

    def getCharacteristics(self, peData, fileData):
        self.characteristics.append(['ID', 1])  # Represents the nunber in the dataset, could put anything here.
        self.characteristics.append(['md5', hashlib.md5(fileData.read()).hexdigest()])
        self.characteristics.append(['Machine', peData.FILE_HEADER.Machine])
        self.characteristics.append(['SizeOfOptionalHeader', peData.FILE_HEADER.SizeOfOptionalHeader])
        self.characteristics.append(['Characteristics', peData.FILE_HEADER.Characteristics])
        self.characteristics.append(['MajorLinkerVersion', peData.OPTIONAL_HEADER.MajorLinkerVersion])
        self.characteristics.append(['MinorLinkerVersion', peData.OPTIONAL_HEADER.MinorLinkerVersion])
        self.characteristics.append(['SizeOfCode', peData.OPTIONAL_HEADER.SizeOfCode])
        self.characteristics.append(['SizeOfInitializedData', peData.OPTIONAL_HEADER.SizeOfInitializedData])
        self.characteristics.append(['SizeOfUninitializedData', peData.OPTIONAL_HEADER.SizeOfUninitializedData])
        self.characteristics.append(['AddressOfEntryPoint', peData.OPTIONAL_HEADER.AddressOfEntryPoint])
        self.characteristics.append(['BaseOfCode', peData.OPTIONAL_HEADER.BaseOfCode])
        try:
            self.characteristics.append(['BaseOfData', peData.OPTIONAL_HEADER.BaseOfData])
        except AttributeError:
            self.characteristics.append(['BaseOfData', 0])

        self.characteristics.append(['ImageBase', peData.OPTIONAL_HEADER.ImageBase])
        self.characteristics.append(['SectionAlignment', peData.OPTIONAL_HEADER.SectionAlignment])
        self.characteristics.append(['FileAlignment', peData.OPTIONAL_HEADER.FileAlignment])
        self.characteristics.append(['MajorOperatingSystemVersion', peData.OPTIONAL_HEADER.MajorOperatingSystemVersion])
        self.characteristics.append(['MinorOperatingSystemVersion', peData.OPTIONAL_HEADER.MinorOperatingSystemVersion])
        self.characteristics.append(['MajorImageVersion', peData.OPTIONAL_HEADER.MajorImageVersion])
        self.characteristics.append(['MinorImageVersion', peData.OPTIONAL_HEADER.MinorImageVersion])
        self.characteristics.append(['MajorSubsystemVersion', peData.OPTIONAL_HEADER.MajorSubsystemVersion])
        self.characteristics.append(['MinorSubsystemVersion', peData.OPTIONAL_HEADER.MinorSubsystemVersion])
        self.characteristics.append(['SizeOfImage', peData.OPTIONAL_HEADER.SizeOfImage])
        self.characteristics.append(['SizeOfHeaders', peData.OPTIONAL_HEADER.SizeOfHeaders])
        self.characteristics.append(['CheckSum', peData.OPTIONAL_HEADER.CheckSum])
        self.characteristics.append(['Subsystem', peData.OPTIONAL_HEADER.Subsystem])
        self.characteristics.append(['DllCharacteristics', peData.OPTIONAL_HEADER.DllCharacteristics])
        self.characteristics.append(['SizeOfStackReserve', peData.OPTIONAL_HEADER.SizeOfStackReserve])
        self.characteristics.append(['SizeOfStackCommit', peData.OPTIONAL_HEADER.SizeOfStackCommit])
        self.characteristics.append(['SizeOfHeapReserve', peData.OPTIONAL_HEADER.SizeOfHeapReserve])
        self.characteristics.append(['SizeOfHeapCommit', peData.OPTIONAL_HEADER.SizeOfHeapCommit])
        self.characteristics.append(['LoaderFlags', peData.OPTIONAL_HEADER.LoaderFlags])
        self.characteristics.append(['NumberOfRvaAndSizes', peData.OPTIONAL_HEADER.NumberOfRvaAndSizes])

        entropy = list(map(lambda x: x.get_entropy(), peData.sections))
        raw_sizes = list(map(lambda x: x.SizeOfRawData, peData.sections))
        virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, peData.sections))
        self.characteristics.append(['SectionsNb', len(peData.sections)])
        self.characteristics.append(['SectionsMeanEntropy', sum(entropy) / float(len(entropy))])
        self.characteristics.append(['SectionsMinEntropy', min(entropy)])
        self.characteristics.append(['SectionsMaxEntropy', max(entropy)])
        self.characteristics.append(['SectionsMeanRawsize', sum(raw_sizes) / float(len(raw_sizes))])
        self.characteristics.append(['SectionsMinRawsize', min(raw_sizes)])
        self.characteristics.append(['SectionMaxRawsize', max(raw_sizes)])
        self.characteristics.append(['SectionsMeanVirtualsize', sum(virtual_sizes) / float(len(virtual_sizes))])
        self.characteristics.append(['SectionsMinVirtualsize', min(virtual_sizes)])
        self.characteristics.append(['SectionMaxVirtualsize', max(virtual_sizes)])

        try:
            self.characteristics.append(['ImportsNbDLL', len(peData.DIRECTORY_ENTRY_IMPORT)])
            imports = sum([x.imports for x in peData.DIRECTORY_ENTRY_IMPORT], [])
            self.characteristics.append(['ImportsNb', len(imports)])
            self.characteristics.append(['ImportsNbOrdinal', len(list(filter(lambda x: x.name is None, imports)))])
        # no imports
        except AttributeError:
            self.characteristics.append(['ImportsNbDLL', 0])
            self.characteristics.append(['ImportsNb', 0])
            self.characteristics.append(['ImportsNbOrdinal', 0])

        try:
            self.characteristics.append(['ExportNb', len(peData.DIRECTORY_ENTRY_EXPORT.symbols)])
        # No exports
        except AttributeError:
            self.characteristics.append(['ExportNb', 0])

        resources = self.get_resources(peData)

        self.characteristics.append(['ResourcesNb', len(resources)])
        if len(resources) > 0:
            entropy = list(map(lambda x: x[0], resources))
            self.characteristics.append(['ResourcesMeanEntropy', sum(entropy) / float(len(entropy))])
            self.characteristics.append(['ResourcesMinEntropy', min(entropy)])
            self.characteristics.append(['ResourcesMaxEntropy', max(entropy)])

            sizes = list(map(lambda x: x[1], resources))
            self.characteristics.append(['ResourcesMeanSize', sum(sizes) / float(len(sizes))])
            self.characteristics.append(['ResourcesMinSize', min(sizes)])
            self.characteristics.append(['ResourcesMaxSize', max(sizes)])
        # no resources
        else:
            self.characteristics.append(['ResourcesMeanEntropy', 0])
            self.characteristics.append(['ResourcesMinEntropy', 0])
            self.characteristics.append(['ResourcesMaxEntropy', 0])
            self.characteristics.append(['ResourcesMeanSize', 0])
            self.characteristics.append(['ResourcesMinSize', 0])
            self.characteristics.append(['ResourcesMaxSize', 0])

        try:
            self.characteristics.append(['LoadConfigurationSize', peData.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size])
        # config size = 0
        except AttributeError:
            self.characteristics.append(['LoadConfigurationSize', 0])

        try:
            version_infos = self.get_version_info(peData)
            self.characteristics.append(['VersionInformationSize', len(version_infos.keys())])
        except AttributeError:
            self.characteristics.append(['VersionInformationSize', 0])

        # We can't define this as Legitimate files are software that don't
        # behave like malware and are useful and harmless to the users.
        self.characteristics.append(['legitimate', None])

    # newFeatureExtractor = FeatureExtractor(path='b.exe')
# attributesToTest_df = newFeatureExtractor.getFileFeatures()
# print(attributesToTest_df.head())
# attributesToTest_df.to_csv("data3.csv",index=False)  #uncomment if you want to see dataframe written to file
