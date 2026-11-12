package control

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/k4ran909/whalescale/gen/whalescale/v1"
	"github.com/k4ran909/whalescale/internal/passwd"
	"github.com/k4ran909/whalescale/internal/store"
)

// settingsProto lists every console-changeable setting with where its value
// comes from.
func (a *Admin) settingsProto(ctx context.Context) ([]*v1.Setting, error) {
	saved, err := a.svc.ReloadSettings(ctx)
	if err != nil {
		return nil, err
	}
	live, conf := a.svc.Settings(), a.svc.ConfigSettings()
	val := func(st Settings, name string) string {
		switch name {
		case SettingFlowLogs:
			return strconv.FormatBool(st.FlowLogs)
		case SettingPostQuantum:
			return strconv.FormatBool(st.PostQuantum)
		case SettingGatewayDomain:
			return st.GatewayDomain
		}
		return ""
	}
	var out []*v1.Setting
	for _, name := range SettingNames {
		out = append(out, &v1.Setting{Name: name, Value: val(live, name), ConfigValue: val(conf, name), FromConsole: saved[name]})
	}
	return out, nil
}

func (a *Admin) GetSettings(ctx context.Context, req *connect.Request[v1.GetSettingsRequest]) (*connect.Response[v1.GetSettingsResponse], error) {
	if _, err := a.auth(ctx, req); err != nil {
		return nil, err
	}
	settings, err := a.settingsProto(ctx)
	if err != nil {
		return nil, internal(a, "get settings", err)
	}
	resp := &v1.GetSettingsResponse{Settings: settings, DnsSuffix: a.svc.cfg.DNSSuffix}
	for _, r := range a.svc.CurrentPolicy().SSH {
		resp.SshRules++
		if r.Record {
			resp.SshRecordedRules++
		}
	}
	return connect.NewResponse(resp), nil
}

func (a *Admin) UpdateSetting(ctx context.Context, req *connect.Request[v1.UpdateSettingRequest]) (*connect.Response[v1.UpdateSettingResponse], error) {
	id, err := a.auth(ctx, req)
	if err != nil {
		return nil, err
	}
	m := req.Msg
	if !m.UseConfig {
		if _, err := NormalizeSetting(m.Name, m.Value); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	if err := a.svc.SaveSetting(ctx, m.Name, m.Value, m.UseConfig); err != nil {
		if strings.HasPrefix(err.Error(), "unknown setting") {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return nil, internal(a, "update setting", err)
	}
	if m.UseConfig {
		a.audit(ctx, id, "setting reset to the config file", "setting", m.Name)
	} else {
		a.audit(ctx, id, "setting changed", "setting", m.Name, "value", m.Value)
	}
	settings, err := a.settingsProto(ctx)
	if err != nil {
		return nil, internal(a, "get settings", err)
	}
	return connect.NewResponse(&v1.UpdateSettingResponse{Settings: settings}), nil
}

func consoleAccountProto(ad *store.Admin) *v1.ConsoleAccount {
	return &v1.ConsoleAccount{Name: ad.Name, CreatedAt: timestamppb.New(ad.CreatedAt), TwoFactor: ad.TwoFactor, Passkeys: uint32(ad.Passkeys)}
}

func (a *Admin) ListConsoleAccounts(ctx context.Context, req *connect.Request[v1.ListConsoleAccountsRequest]) (*connect.Response[v1.ListConsoleAccountsResponse], error) {
	id, err := a.auth(ctx, req)
	if err != nil {
		return nil, err
	}
	admins, err := a.svc.store.ListAdmins(ctx)
	if err != nil {
		return nil, internal(a, "list console accounts", err)
	}
	resp := &v1.ListConsoleAccountsResponse{}
	if id.method == "admin" {
		resp.You = id.name
	}
	for i := range admins {
		resp.Accounts = append(resp.Accounts, consoleAccountProto(&admins[i]))
	}
	return connect.NewResponse(resp), nil
}

func (a *Admin) CreateConsoleAccount(ctx context.Context, req *connect.Request[v1.CreateConsoleAccountRequest]) (*connect.Response[v1.CreateConsoleAccountResponse], error) {
	id, err := a.auth(ctx, req)
	if err != nil {
		return nil, err
	}
	name := strings.ToLower(strings.TrimSpace(req.Msg.Name))
	if !store.ValidName(name) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a name is lowercase letters, digits and dashes, like priya or ops-team"))
	}
	pw := store.RandomCode(20)
	hash, err := passwd.Hash(pw)
	if err != nil {
		return nil, internal(a, "hash password", err)
	}
	ad, err := a.svc.store.CreateAdmin(ctx, name, hash)
	if errors.Is(err, store.ErrAlreadyExists) {
		return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("a console account with that name exists"))
	}
	if err != nil {
		return nil, internal(a, "create console account", err)
	}
	// The member's own machines go under a user of the same name.
	if _, err := a.svc.store.CreateUser(ctx, name); err != nil && !errors.Is(err, store.ErrAlreadyExists) {
		a.svc.log.Warn("create user for console account", "name", name, "err", err)
	}
	a.audit(ctx, id, "console account created", "account", name)
	return connect.NewResponse(&v1.CreateConsoleAccountResponse{Account: consoleAccountProto(ad), Password: pw}), nil
}

func (a *Admin) DeleteConsoleAccount(ctx context.Context, req *connect.Request[v1.DeleteConsoleAccountRequest]) (*connect.Response[v1.DeleteConsoleAccountResponse], error) {
	id, err := a.auth(ctx, req)
	if err != nil {
		return nil, err
	}
	name := req.Msg.Name
	if id.method == "admin" && id.name == name {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("you can't delete the account you're signed in with"))
	}
	if n, err := a.svc.store.AdminCount(ctx); err == nil && n <= 1 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("that's the last console account"))
	}
	if err := a.svc.store.DeleteAdmin(ctx, name); err != nil {
		return nil, notFoundOr(a, "delete console account", err)
	}
	a.audit(ctx, id, "console account deleted", "account", name)
	return connect.NewResponse(&v1.DeleteConsoleAccountResponse{}), nil
}
