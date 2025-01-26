package common

import (
	"errors"
	"fmt"
	"reflect"

	mapset "github.com/deckarep/golang-set/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type Permission = string
type Permissions = mapset.Set[Permission]

const (
	PermissionUser  Permission = "user"
	PermissionAdmin Permission = "admin"
)

var PermissionsType = reflect.TypeFor[Permissions]()

func NewPermissions(vals ...Permission) Permissions {
	return Permissions(mapset.NewSet(vals...))
}

// Mongodb's bson custom encoding/decoding

func PermissionsEncoder(
	_ bson.EncodeContext,
	vw bson.ValueWriter,
	val reflect.Value,
) error {
	if !val.IsValid() || val.Type() != PermissionsType {
		return bson.ValueEncoderError{
			Name:     "permissionsEncoder",
			Types:    []reflect.Type{PermissionsType},
			Received: val,
		}
	}
	permissions := val.Interface().(Permissions)

	arrWriter, err := vw.WriteArray()
	if err != nil {
		return err
	}
	for _, p := range permissions.ToSlice() {
		vw, err = arrWriter.WriteArrayElement()
		if err != nil {
			return err
		}
		err = vw.WriteString(p)
		if err != nil {
			return err
		}
	}
	err = arrWriter.WriteArrayEnd()
	return err
}

func PermissionsDecoder(
	_ bson.DecodeContext,
	vr bson.ValueReader,
	val reflect.Value,
) error {
	if !val.IsValid() || val.Type() != PermissionsType {
		return bson.ValueEncoderError{
			Name:     "permissionsDecoder",
			Types:    []reflect.Type{PermissionsType},
			Received: val,
		}
	}

	perms := NewPermissions()

	switch vr.Type() {
	case bson.TypeArray:
		arrReader, err := vr.ReadArray()
		if err != nil {
			return err
		}
		for {
			vr, err := arrReader.ReadValue()
			if err != nil {
				if errors.Is(err, bson.ErrEOA) {
					break
				}
				return err
			}
			perm, err := vr.ReadString()
			if err != nil {
				return err
			}
			perms.Add(perm)
		}
		val.Set(reflect.ValueOf(perms))

	default:
		return fmt.Errorf(
			"received invalid BSON type to decode into Permissions: %s",
			vr.Type())
	}

	return nil
}
