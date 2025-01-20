package authpher

type PermissionRequired[P comparable, C any] struct {
	Permission P
}
