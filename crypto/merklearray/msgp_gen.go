package merklearray

// Code generated by github.com/algorand/msgp DO NOT EDIT.

import (
	"github.com/algorand/msgp/msgp"
)

// The following msgp objects are implemented in this file:
// Layer
//   |-----> MarshalMsg
//   |-----> CanMarshalMsg
//   |-----> (*) UnmarshalMsg
//   |-----> (*) CanUnmarshalMsg
//   |-----> Msgsize
//   |-----> MsgIsZero
//
// Tree
//   |-----> (*) MarshalMsg
//   |-----> (*) CanMarshalMsg
//   |-----> (*) UnmarshalMsg
//   |-----> (*) CanUnmarshalMsg
//   |-----> (*) Msgsize
//   |-----> (*) MsgIsZero
//

// MarshalMsg implements msgp.Marshaler
func (z Layer) MarshalMsg(b []byte) (o []byte) {
	o = msgp.Require(b, z.Msgsize())
	if z == nil {
		o = msgp.AppendNil(o)
	} else {
		o = msgp.AppendArrayHeader(o, uint32(len(z)))
	}
	for za0001 := range z {
		o = z[za0001].MarshalMsg(o)
	}
	return
}

func (_ Layer) CanMarshalMsg(z interface{}) bool {
	_, ok := (z).(Layer)
	if !ok {
		_, ok = (z).(*Layer)
	}
	return ok
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Layer) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var zb0002 int
	var zb0003 bool
	zb0002, zb0003, bts, err = msgp.ReadArrayHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	if zb0003 {
		(*z) = nil
	} else if (*z) != nil && cap((*z)) >= zb0002 {
		(*z) = (*z)[:zb0002]
	} else {
		(*z) = make(Layer, zb0002)
	}
	for zb0001 := range *z {
		bts, err = (*z)[zb0001].UnmarshalMsg(bts)
		if err != nil {
			err = msgp.WrapError(err, zb0001)
			return
		}
	}
	o = bts
	return
}

func (_ *Layer) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*Layer)
	return ok
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z Layer) Msgsize() (s int) {
	s = msgp.ArrayHeaderSize
	for za0001 := range z {
		s += z[za0001].Msgsize()
	}
	return
}

// MsgIsZero returns whether this is a zero value
func (z Layer) MsgIsZero() bool {
	return len(z) == 0
}

// MarshalMsg implements msgp.Marshaler
func (z *Tree) MarshalMsg(b []byte) (o []byte) {
	o = msgp.Require(b, z.Msgsize())
	// omitempty: check for empty values
	zb0003Len := uint32(1)
	var zb0003Mask uint8 /* 2 bits */
	if len((*z).Levels) == 0 {
		zb0003Len--
		zb0003Mask |= 0x2
	}
	// variable map header, size zb0003Len
	o = append(o, 0x80|uint8(zb0003Len))
	if zb0003Len != 0 {
		if (zb0003Mask & 0x2) == 0 { // if not empty
			// string "lvls"
			o = append(o, 0xa4, 0x6c, 0x76, 0x6c, 0x73)
			if (*z).Levels == nil {
				o = msgp.AppendNil(o)
			} else {
				o = msgp.AppendArrayHeader(o, uint32(len((*z).Levels)))
			}
			for zb0001 := range (*z).Levels {
				if (*z).Levels[zb0001] == nil {
					o = msgp.AppendNil(o)
				} else {
					o = msgp.AppendArrayHeader(o, uint32(len((*z).Levels[zb0001])))
				}
				for zb0002 := range (*z).Levels[zb0001] {
					o = (*z).Levels[zb0001][zb0002].MarshalMsg(o)
				}
			}
		}
	}
	return
}

func (_ *Tree) CanMarshalMsg(z interface{}) bool {
	_, ok := (z).(*Tree)
	return ok
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Tree) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0003 int
	var zb0004 bool
	zb0003, zb0004, bts, err = msgp.ReadMapHeaderBytes(bts)
	if _, ok := err.(msgp.TypeError); ok {
		zb0003, zb0004, bts, err = msgp.ReadArrayHeaderBytes(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		if zb0003 > 0 {
			zb0003--
			var zb0005 int
			var zb0006 bool
			zb0005, zb0006, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array", "Levels")
				return
			}
			if zb0006 {
				(*z).Levels = nil
			} else if (*z).Levels != nil && cap((*z).Levels) >= zb0005 {
				(*z).Levels = ((*z).Levels)[:zb0005]
			} else {
				(*z).Levels = make([]Layer, zb0005)
			}
			for zb0001 := range (*z).Levels {
				var zb0007 int
				var zb0008 bool
				zb0007, zb0008, bts, err = msgp.ReadArrayHeaderBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "struct-from-array", "Levels", zb0001)
					return
				}
				if zb0008 {
					(*z).Levels[zb0001] = nil
				} else if (*z).Levels[zb0001] != nil && cap((*z).Levels[zb0001]) >= zb0007 {
					(*z).Levels[zb0001] = ((*z).Levels[zb0001])[:zb0007]
				} else {
					(*z).Levels[zb0001] = make(Layer, zb0007)
				}
				for zb0002 := range (*z).Levels[zb0001] {
					bts, err = (*z).Levels[zb0001][zb0002].UnmarshalMsg(bts)
					if err != nil {
						err = msgp.WrapError(err, "struct-from-array", "Levels", zb0001, zb0002)
						return
					}
				}
			}
		}
		if zb0003 > 0 {
			err = msgp.ErrTooManyArrayFields(zb0003)
			if err != nil {
				err = msgp.WrapError(err, "struct-from-array")
				return
			}
		}
	} else {
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		if zb0004 {
			(*z) = Tree{}
		}
		for zb0003 > 0 {
			zb0003--
			field, bts, err = msgp.ReadMapKeyZC(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
			switch string(field) {
			case "lvls":
				var zb0009 int
				var zb0010 bool
				zb0009, zb0010, bts, err = msgp.ReadArrayHeaderBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Levels")
					return
				}
				if zb0010 {
					(*z).Levels = nil
				} else if (*z).Levels != nil && cap((*z).Levels) >= zb0009 {
					(*z).Levels = ((*z).Levels)[:zb0009]
				} else {
					(*z).Levels = make([]Layer, zb0009)
				}
				for zb0001 := range (*z).Levels {
					var zb0011 int
					var zb0012 bool
					zb0011, zb0012, bts, err = msgp.ReadArrayHeaderBytes(bts)
					if err != nil {
						err = msgp.WrapError(err, "Levels", zb0001)
						return
					}
					if zb0012 {
						(*z).Levels[zb0001] = nil
					} else if (*z).Levels[zb0001] != nil && cap((*z).Levels[zb0001]) >= zb0011 {
						(*z).Levels[zb0001] = ((*z).Levels[zb0001])[:zb0011]
					} else {
						(*z).Levels[zb0001] = make(Layer, zb0011)
					}
					for zb0002 := range (*z).Levels[zb0001] {
						bts, err = (*z).Levels[zb0001][zb0002].UnmarshalMsg(bts)
						if err != nil {
							err = msgp.WrapError(err, "Levels", zb0001, zb0002)
							return
						}
					}
				}
			default:
				err = msgp.ErrNoField(string(field))
				if err != nil {
					err = msgp.WrapError(err)
					return
				}
			}
		}
	}
	o = bts
	return
}

func (_ *Tree) CanUnmarshalMsg(z interface{}) bool {
	_, ok := (z).(*Tree)
	return ok
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *Tree) Msgsize() (s int) {
	s = 1 + 5 + msgp.ArrayHeaderSize
	for zb0001 := range (*z).Levels {
		s += msgp.ArrayHeaderSize
		for zb0002 := range (*z).Levels[zb0001] {
			s += (*z).Levels[zb0001][zb0002].Msgsize()
		}
	}
	return
}

// MsgIsZero returns whether this is a zero value
func (z *Tree) MsgIsZero() bool {
	return (len((*z).Levels) == 0)
}
