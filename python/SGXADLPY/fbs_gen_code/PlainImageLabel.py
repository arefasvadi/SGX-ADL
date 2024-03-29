# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers

class PlainImageLabel(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAsPlainImageLabel(cls, buf, offset):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = PlainImageLabel()
        x.Init(buf, n + offset)
        return x

    # PlainImageLabel
    def Init(self, buf, pos):
        self._tab = flatbuffers.table.Table(buf, pos)

    # PlainImageLabel
    def ImgContent(self, j):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Float32Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 4))
        return 0

    # PlainImageLabel
    def ImgContentAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Float32Flags, o)
        return 0

    # PlainImageLabel
    def ImgContentLength(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

    # PlainImageLabel
    def LabelContent(self, j):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            a = self._tab.Vector(o)
            return self._tab.Get(flatbuffers.number_types.Float32Flags, a + flatbuffers.number_types.UOffsetTFlags.py_type(j * 4))
        return 0

    # PlainImageLabel
    def LabelContentAsNumpy(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.GetVectorAsNumpy(flatbuffers.number_types.Float32Flags, o)
        return 0

    # PlainImageLabel
    def LabelContentLength(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(6))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

def PlainImageLabelStart(builder): builder.StartObject(2)
def PlainImageLabelAddImgContent(builder, imgContent): builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(imgContent), 0)
def PlainImageLabelStartImgContentVector(builder, numElems): return builder.StartVector(4, numElems, 4)
def PlainImageLabelAddLabelContent(builder, labelContent): builder.PrependUOffsetTRelativeSlot(1, flatbuffers.number_types.UOffsetTFlags.py_type(labelContent), 0)
def PlainImageLabelStartLabelContentVector(builder, numElems): return builder.StartVector(4, numElems, 4)
def PlainImageLabelEnd(builder): return builder.EndObject()
