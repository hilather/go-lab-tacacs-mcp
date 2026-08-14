// Package server will translate RADIUS packets to AAA operations.
//
// It may import aaa and the RADIUS codec. It must not import TACACS
// or policy evaluation. There is no production listener here.
package server
