/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { observer } from "mobx-react";
import Link from "next/link";
// icons
import { Settings2 } from "lucide-react";
// plane internal packages
import { getButtonStyling } from "@plane/propel/button";
import type { TInstanceAuthenticationMethodKeys } from "@plane/types";
import { ToggleSwitch } from "@plane/ui";
import { cn } from "@plane/utils";
// hooks
import { useInstance } from "@/hooks/store";

type Props = {
  disabled: boolean;
  updateConfig: (key: TInstanceAuthenticationMethodKeys, value: string) => void;
};

export const KeycloakConfiguration = observer(function KeycloakConfiguration(props: Props) {
  const { disabled, updateConfig } = props;
  // store
  const { formattedConfig } = useInstance();
  // derived values
  const KeycloakConfig = formattedConfig?.IS_KEYCLOAK_ENABLED ?? "";
  const KeycloakConfigured =
    !!formattedConfig?.KEYCLOAK_SERVER_URL &&
    !!formattedConfig?.KEYCLOAK_REALM &&
    !!formattedConfig?.KEYCLOAK_CLIENT_ID &&
    !!formattedConfig?.KEYCLOAK_CLIENT_SECRET;

  return (
    <>
      {KeycloakConfigured ? (
        <div className="flex items-center gap-4">
          <Link href="/authentication/keycloak" className={cn(getButtonStyling("link", "base"), "font-medium")}>
            Edit
          </Link>
          <ToggleSwitch
            value={Boolean(parseInt(KeycloakConfig))}
            onChange={() => {
              if (Boolean(parseInt(KeycloakConfig)) === true) {
                updateConfig("IS_KEYCLOAK_ENABLED", "0");
              } else {
                updateConfig("IS_KEYCLOAK_ENABLED", "1");
              }
            }}
            size="sm"
            disabled={disabled}
          />
        </div>
      ) : (
        <Link href="/authentication/keycloak" className={cn(getButtonStyling("secondary", "base"), "text-tertiary")}>
          <Settings2 className="h-4 w-4 p-0.5 text-tertiary" />
          Configure
        </Link>
      )}
    </>
  );
});
