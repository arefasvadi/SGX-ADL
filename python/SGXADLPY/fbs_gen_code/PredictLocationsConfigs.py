# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers
from flatbuffers.compat import import_numpy
np = import_numpy()

class PredictLocationsConfigs(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAs(cls, buf, offset=0):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = PredictLocationsConfigs()
        x.Init(buf, n + offset)
        return x

    @classmethod
    def GetRootAsPredictLocationsConfigs(cls, buf, offset=0):
        """This method is deprecated. Please switch to GetRootAs."""
        return cls.GetRootAs(buf, offset)
    # PredictLocationsConfigs
    def Init(self, buf, pos):
        self._tab = flatbuffers.table.Table(buf, pos)

    # PredictLocationsConfigs
    def DatasetDir(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def DecDatasetDir(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def NetworkArchPath(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def WeightsLoadDir(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def PredsSaveDir(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(12))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def SnapshotDir(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(14))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def ClientPkSigFile(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(16))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def SgxSkSigFile(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(18))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def SgxPkSigFile(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(20))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def SignedTaskConfigPath(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(22))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def ClientAesGcmKeyFile(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(24))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def SgxAesGcmKeyFile(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(26))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

    # PredictLocationsConfigs
    def DataConfigPath(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(28))
        if o != 0:
            return self._tab.String(o + self._tab.Pos)
        return None

def PredictLocationsConfigsStart(builder): builder.StartObject(13)
def Start(builder):
    return PredictLocationsConfigsStart(builder)
def PredictLocationsConfigsAddDatasetDir(builder, datasetDir): builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(datasetDir), 0)
def AddDatasetDir(builder, datasetDir):
    return PredictLocationsConfigsAddDatasetDir(builder, datasetDir)
def PredictLocationsConfigsAddDecDatasetDir(builder, decDatasetDir): builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(decDatasetDir), 0)
def AddDecDatasetDir(builder, decDatasetDir):
    return PredictLocationsConfigsAddDecDatasetDir(builder, decDatasetDir)
def PredictLocationsConfigsAddNetworkArchPath(builder, networkArchPath): builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(networkArchPath), 0)
def AddNetworkArchPath(builder, networkArchPath):
    return PredictLocationsConfigsAddNetworkArchPath(builder, networkArchPath)
def PredictLocationsConfigsAddWeightsLoadDir(builder, weightsLoadDir): builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(weightsLoadDir), 0)
def AddWeightsLoadDir(builder, weightsLoadDir):
    return PredictLocationsConfigsAddWeightsLoadDir(builder, weightsLoadDir)
def PredictLocationsConfigsAddPredsSaveDir(builder, predsSaveDir): builder.PrependUOffsetTRelativeSlot(4, flatbuffers.number_types.UOffsetTFlags.py_type(predsSaveDir), 0)
def AddPredsSaveDir(builder, predsSaveDir):
    return PredictLocationsConfigsAddPredsSaveDir(builder, predsSaveDir)
def PredictLocationsConfigsAddSnapshotDir(builder, snapshotDir): builder.PrependUOffsetTRelativeSlot(5, flatbuffers.number_types.UOffsetTFlags.py_type(snapshotDir), 0)
def AddSnapshotDir(builder, snapshotDir):
    return PredictLocationsConfigsAddSnapshotDir(builder, snapshotDir)
def PredictLocationsConfigsAddClientPkSigFile(builder, clientPkSigFile): builder.PrependUOffsetTRelativeSlot(6, flatbuffers.number_types.UOffsetTFlags.py_type(clientPkSigFile), 0)
def AddClientPkSigFile(builder, clientPkSigFile):
    return PredictLocationsConfigsAddClientPkSigFile(builder, clientPkSigFile)
def PredictLocationsConfigsAddSgxSkSigFile(builder, sgxSkSigFile): builder.PrependUOffsetTRelativeSlot(7, flatbuffers.number_types.UOffsetTFlags.py_type(sgxSkSigFile), 0)
def AddSgxSkSigFile(builder, sgxSkSigFile):
    return PredictLocationsConfigsAddSgxSkSigFile(builder, sgxSkSigFile)
def PredictLocationsConfigsAddSgxPkSigFile(builder, sgxPkSigFile): builder.PrependUOffsetTRelativeSlot(8, flatbuffers.number_types.UOffsetTFlags.py_type(sgxPkSigFile), 0)
def AddSgxPkSigFile(builder, sgxPkSigFile):
    return PredictLocationsConfigsAddSgxPkSigFile(builder, sgxPkSigFile)
def PredictLocationsConfigsAddSignedTaskConfigPath(builder, signedTaskConfigPath): builder.PrependUOffsetTRelativeSlot(9, flatbuffers.number_types.UOffsetTFlags.py_type(signedTaskConfigPath), 0)
def AddSignedTaskConfigPath(builder, signedTaskConfigPath):
    return PredictLocationsConfigsAddSignedTaskConfigPath(builder, signedTaskConfigPath)
def PredictLocationsConfigsAddClientAesGcmKeyFile(builder, clientAesGcmKeyFile): builder.PrependUOffsetTRelativeSlot(10, flatbuffers.number_types.UOffsetTFlags.py_type(clientAesGcmKeyFile), 0)
def AddClientAesGcmKeyFile(builder, clientAesGcmKeyFile):
    return PredictLocationsConfigsAddClientAesGcmKeyFile(builder, clientAesGcmKeyFile)
def PredictLocationsConfigsAddSgxAesGcmKeyFile(builder, sgxAesGcmKeyFile): builder.PrependUOffsetTRelativeSlot(11, flatbuffers.number_types.UOffsetTFlags.py_type(sgxAesGcmKeyFile), 0)
def AddSgxAesGcmKeyFile(builder, sgxAesGcmKeyFile):
    return PredictLocationsConfigsAddSgxAesGcmKeyFile(builder, sgxAesGcmKeyFile)
def PredictLocationsConfigsAddDataConfigPath(builder, dataConfigPath): builder.PrependUOffsetTRelativeSlot(12, flatbuffers.number_types.UOffsetTFlags.py_type(dataConfigPath), 0)
def AddDataConfigPath(builder, dataConfigPath):
    return PredictLocationsConfigsAddDataConfigPath(builder, dataConfigPath)
def PredictLocationsConfigsEnd(builder): return builder.EndObject()
def End(builder):
    return PredictLocationsConfigsEnd(builder)