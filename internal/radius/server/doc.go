// Package server translates RADIUS packets to AAA operations.
//
// Accounting-Request is validated (Request Authenticator, inbound
// Message-Authenticator if present), mapped onto the five MVP status
// types, and recorded through aaa.RecordRADIUSAccounting. Accounting-
// Response always inserts Message-Authenticator first. Access is still
// a structural Access-Reject stub (PAP/CHAP is a later PR).
//
// This package may import the RADIUS codec, attributes, crypto, and aaa.
// It must not import TACACS, policy evaluation, or API adapters.
package server
