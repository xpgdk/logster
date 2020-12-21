defmodule Logster.JSONFormatter do
  def format(params) do
    params
    |> Enum.into(%{})
    |> Jason.encode!()
  end

  def format_on_call(params), do: format(params)
end
