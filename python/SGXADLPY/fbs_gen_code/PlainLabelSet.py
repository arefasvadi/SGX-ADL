# automatically generated by the FlatBuffers compiler, do not modify

# namespace: 

import flatbuffers

class PlainLabelSet(object):
    __slots__ = ['_tab']

    @classmethod
    def GetRootAsPlainLabelSet(cls, buf, offset):
        n = flatbuffers.encode.Get(flatbuffers.packer.uoffset, buf, offset)
        x = PlainLabelSet()
        x.Init(buf, n + offset)
        return x

    # PlainLabelSet
    def Init(self, buf, pos):
        self._tab = flatbuffers.table.Table(buf, pos)

    # PlainLabelSet
    def Images(self, j):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            x = self._tab.Vector(o)
            x += flatbuffers.number_types.UOffsetTFlags.py_type(j) * 4
            x = self._tab.Indirect(x)
            from .PlainLabel import PlainLabel
            obj = PlainLabel()
            obj.Init(self._tab.Bytes, x)
            return obj
        return None

    # PlainLabelSet
    def ImagesLength(self):
        o = flatbuffers.number_types.UOffsetTFlags.py_type(self._tab.Offset(4))
        if o != 0:
            return self._tab.VectorLen(o)
        return 0

def PlainLabelSetStart(builder): builder.StartObject(1)
def PlainLabelSetAddImages(builder, images): builder.PrependUOffsetTRelativeSlot(0, flatbuffers.number_types.UOffsetTFlags.py_type(images), 0)
def PlainLabelSetStartImagesVector(builder, numElems): return builder.StartVector(4, numElems, 4)
def PlainLabelSetEnd(builder): return builder.EndObject()
