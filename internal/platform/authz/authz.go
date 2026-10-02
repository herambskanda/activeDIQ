// Package authz is the permission and scope kernel package (blueprint §5.1, EP-6).
// The skeleton carries only the Permission type that extension-point interfaces name;
// evaluation arrives with the first endpoint (T-0046).
package authz

// Permission names one thing a principal may be allowed to do, for example "objects.user.create".
type Permission string
