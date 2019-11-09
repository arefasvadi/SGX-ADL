# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers

class AESGCM128Enc(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAsAESGCM128Enc(cls, buf, offset):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = AESGCM128Enc()
        x.Init(buf, n + offset)
        return x

    # AESGCM128Enc
    def Init(self, buf, pos):
        self._tab = flatbuffers.table.Table(buf, pos)

    # AESGCM128Enc
    def EncContent(self, j):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 1))
        return 0

    # AESGCM128Enc
    def EncContentAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Uint8Flags, o)
        return 0

    # AESGCM128Enc
    def EncContentLength(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # AESGCM128Enc
    def Iv(self, j):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 1))
        return 0

    # AESGCM128Enc
    def IvAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Uint8Flags, o)
        return 0

    # AESGCM128Enc
    def IvLength(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # AESGCM128Enc
    def Mac(self, j):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 1))
        return 0

    # AESGCM128Enc
    def MacAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Uint8Flags, o)
        return 0

    # AESGCM128Enc
    def MacLength(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(8))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # AESGCM128Enc
    def Aad(self, j):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Uint8Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 1))
        return 0

    # AESGCM128Enc
    def AadAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Uint8Flags, o)
        return 0

    # AESGCM128Enc
    def AadLength(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(10))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

def AESGCM128EncStart(builder): builder.StartObject(4)
def AESGCM128EncAddEncContent(builder, encContent): builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(encContent), 0)
def AESGCM128EncStartEncContentVector(builder, numElems): return builder.StartVector(1, numElems, 1)
def AESGCM128EncAddIv(builder, iv): builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(iv), 0)
def AESGCM128EncStartIvVector(builder, numElems): return builder.StartVector(1, numElems, 1)
def AESGCM128EncAddMac(builder, mac): builder.PrependUOffsetTRelativeSlot(2, flatbuffers.number_types.UOffsetTFlags.py_type(mac), 0)
def AESGCM128EncStartMacVector(builder, numElems): return builder.StartVector(1, numElems, 1)
def AESGCM128EncAddAad(builder, aad): builder.PrependUOffsetTRelativeSlot(3, flatbuffers.number_types.UOffsetTFlags.py_type(aad), 0)
def AESGCM128EncStartAadVector(builder, numElems): return builder.StartVector(1, numElems, 1)
def AESGCM128EncEnd(builder): return builder.EndObject()
