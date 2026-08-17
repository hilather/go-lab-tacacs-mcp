import { INSECURE_RADIUS_LABEL, RADSEC_HINT, UDP_RADIUS_HINT } from "../ui/radius";

export function ProtocolBadge({ protocol }: { protocol: string }) {
  const label = protocol.trim() === "" ? "unknown" : protocol;
  return (
    <span className={`proto-badge proto-badge--${label}`}>
      <span className="visually-hidden">Protocol </span>
      {label}
    </span>
  );
}

export function RoleBadge({ role }: { role: string }) {
  return (
    <span className="role-badge">
      <span className="visually-hidden">Role </span>
      {role}
    </span>
  );
}

export function UDPWarningBadge({ title = UDP_RADIUS_HINT }: { title?: string }) {
  return (
    <span className="warn-badge" title={title}>
      UDP
      <span className="visually-hidden"> — {title}</span>
    </span>
  );
}

export function InsecureRadiusBadge() {
  return (
    <span className="warn-badge" title="Message-Authenticator is not required on this RADIUS endpoint.">
      {INSECURE_RADIUS_LABEL}
    </span>
  );
}

export function RadSecBadge() {
  return (
    <span className="role-badge" title={RADSEC_HINT}>
      RadSec
      <span className="visually-hidden"> — {RADSEC_HINT}</span>
    </span>
  );
}

export function DASBadge() {
  return (
    <span className="role-badge" title="Inbound :3799 RFC 5176 test fixture. Index-only; DAC originate is on RADIUS sessions.">
      DAS
      <span className="visually-hidden"> — inbound :3799 fixture</span>
    </span>
  );
}
