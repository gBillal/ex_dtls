defmodule ExDTLS.Native do
  @moduledoc false

  @on_load :load_nif

  def load_nif do
    path = :filename.join(:code.priv_dir(:ex_dtls), ~c"libdtls")
    :ok = :erlang.load_nif(path, 0)
  end

  def init(_mode_str, _use_srtp, _verify_peer), do: :erlang.nif_error(:nif_not_loaded)

  def init_from_key_cert(_mode_str, _use_srtp, _verify_peer, _pkey, _cert),
    do: :erlang.nif_error(:nif_not_loaded)

  def generate_key_cert(_not_before, _not_after), do: :erlang.nif_error(:nif_not_loaded)

  def get_pkey(_state), do: :erlang.nif_error(:nif_not_loaded)

  def get_cert(_state), do: :erlang.nif_error(:nif_not_loaded)

  def get_peer_cert(_state), do: :erlang.nif_error(:nif_not_loaded)

  def get_cert_fingerprint(_cert), do: :erlang.nif_error(:nif_not_loaded)

  def do_handshake(_state), do: :erlang.nif_error(:nif_not_loaded)

  def handle_timeout(_state), do: :erlang.nif_error(:nif_not_loaded)

  def write_data(_state, _packets), do: :erlang.nif_error(:nif_not_loaded)

  def handle_data(_state, _packets), do: :erlang.nif_error(:nif_not_loaded)

  def exd_close(_state), do: :erlang.nif_error(:nif_not_loaded)
end
