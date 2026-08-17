import { useQuery } from "@tanstack/react-query";
import { exportConfig, listClients, listGroups, listUsers } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { collectRadiusPolicyIDs } from "../ui/radius";

export function useRadiusPolicyOptions(extra: readonly string[] = []): string[] {
  const { hasScope } = useAuth();
  const users = useQuery({
    queryKey: ["users", false],
    queryFn: () => listUsers({ limit: 200 }),
  });
  const groups = useQuery({
    queryKey: ["groups", false],
    queryFn: () => listGroups({ limit: 200 }),
  });
  const clients = useQuery({
    queryKey: ["clients", false],
    queryFn: () => listClients({ limit: 200 }),
  });
  const exported = useQuery({
    queryKey: ["config", "export", "effective"],
    queryFn: () => exportConfig("effective"),
    enabled: hasScope("config:export"),
    retry: false,
  });
  return collectRadiusPolicyIDs({
    ...(users.data?.data.items ? { users: users.data.data.items } : {}),
    ...(groups.data?.data.items ? { groups: groups.data.data.items } : {}),
    ...(clients.data?.data.items ? { clients: clients.data.data.items } : {}),
    ...(exported.data?.data.yaml ? { yaml: exported.data.data.yaml } : {}),
    extra,
  });
}
