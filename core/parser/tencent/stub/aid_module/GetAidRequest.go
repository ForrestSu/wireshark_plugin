// Package aid_module comment
// This file war generated by trpc4videopacket 1.0
// Generated from aid_module.jce
package aid_module

import (
	"fmt"
	"git.code.oa.com/jce/jce"
)

// GetAidRequest struct implement
type GetAidRequest struct {
	CommonInfo CommonInfo `json:"commonInfo,omitempty"`
	MediaInfo  MediaInfo  `json:"mediaInfo,omitempty"`
}

func (st *GetAidRequest) ResetDefault() {
}

// ReadFrom reads  from _is and put into struct.
func (st *GetAidRequest) ReadFrom(_is *jce.Reader) error {
	var err error
	var length int32
	var have bool
	var ty byte
	st.ResetDefault()

	err = st.CommonInfo.ReadBlock(_is, 1, true)
	if err != nil {
		return err
	}

	err = st.MediaInfo.ReadBlock(_is, 2, true)
	if err != nil {
		return err
	}

	_ = err
	_ = length
	_ = have
	_ = ty
	return nil
}

//ReadBlock reads struct from the given tag , require or optional.
func (st *GetAidRequest) ReadBlock(_is *jce.Reader, tag byte, require bool) error {
	var err error
	var have bool
	st.ResetDefault()

	err, have = _is.SkipTo(jce.STRUCT_BEGIN, tag, require)
	if err != nil {
		return err
	}
	if !have {
		if require {
			return fmt.Errorf("require GetAidRequest, but not exist. tag %d", tag)
		}
		return nil

	}

	st.ReadFrom(_is)

	err = _is.SkipToStructEnd()
	if err != nil {
		return err
	}
	_ = have
	return nil
}

//WriteTo encode struct to buffer
func (st *GetAidRequest) WriteTo(_os *jce.Buffer) error {
	var err error
	_ = err

	err = st.CommonInfo.WriteBlock(_os, 1)
	if err != nil {
		return err
	}

	err = st.MediaInfo.WriteBlock(_os, 2)
	if err != nil {
		return err
	}

	return nil
}

//WriteBlock encode struct
func (st *GetAidRequest) WriteBlock(_os *jce.Buffer, tag byte) error {
	var err error
	err = _os.WriteHead(jce.STRUCT_BEGIN, tag)
	if err != nil {
		return err
	}

	st.WriteTo(_os)

	err = _os.WriteHead(jce.STRUCT_END, 0)
	if err != nil {
		return err
	}
	return nil
}