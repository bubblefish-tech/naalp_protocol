# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C10 channels parity cluster for the Ruby SDK (task #174; design-channels.md §1..§20,
# §18, §20): the frozen twenty-channel baseline registry (already ported), plus the channel
# state-machine (ChannelSpec/KindSpec, Channels.channel, Channels.allowed_transition), Spatial's
# TransformCycle structural check (Channels.check_frame_tree), and the Workflow durable
# input/approval gate (Channels.open_workflow_gate / Channels::WorkflowGate) whose crash test
# proves InputGateBypass cannot occur -- mirrors impl/go/channels/channels_test.go and
# impl/rust/src/channels.rs's #[cfg(test)] module.
#
# Grading is F3 non-circular: every channel's kinds/states/transitions/errors are checked against
# the shared independent oracle vectors/channels/<name>/cases.json (the SAME file Go and Rust
# grade against -- NOT produced by this code), so a wrong transcription in any of the twenty
# channels flips this test RED. The AllowedTransition/CheckFrameTree/WorkflowGate verdict
# assertions mirror channels_test.go's TestStateMachine / TestTransformCycle /
# TestWorkflowInputGateBypass byte-for-byte (same from/to pairs, same tree shapes, same gate
# script), so a divergent verdict from either reference flips this test RED.
#
# FAIL-CLOSED anchor (SECURITY-CRITICAL, mutation target): a Workflow task may not reach "running"
# without first passing its input/approval gate (InputGateBypass), and this MUST hold across a
# simulated crash (close -> reopen with no input yet supplied). test_workflow_input_gate_bypass is
# the mutation target: neutering the gate check so Run-before-input succeeds flips it RED.
#
# Written test-first: before this session, Naalp::Channels had no ChannelSpec/KindSpec struct
# types, no Channels.channel/allowed_transition/check_frame_tree, and no WorkflowGate -- so this
# file fails RED (NoMethodError / NameError) until impl/ruby/lib/naalp/channels.rb is extended.
#
# Run:  ruby -Ilib -Itest test/test_channels.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'tmpdir'
require 'naalp'

# Walk up from this test dir to the repository's shared per-channel oracle corpus.
def channel_vectors(name)
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "channels", name, "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/channels/#{name}/cases.json not found"
end

class ChannelsConformance < Minitest::Test
  C = Naalp::Channels::TABLE

  # ---- TestTableMatchesOracle: the frozen impl registry equals the independent per-channel
  # oracle, in both directions (=> Ruby == Go == Rust, which grade the same vectors). ----------

  def test_table_matches_oracle
    assert_equal 20, C.length
    C.each do |ch|
      v = channel_vectors(ch.name.downcase)
      assert_equal v["channel_id"], ch.id, "#{ch.name}: id"
      assert_equal v["name"], ch.name, "#{ch.name}: name"
      assert_equal v["kinds"].length, ch.kinds.length, "#{ch.name}: kind count"
      v["kinds"].each_with_index do |ok, i|
        k = ch.kinds[i]
        assert_equal ok["code"], k.code, "#{ch.name} kind #{i} code"
        assert_equal ok["name"], k.name, "#{ch.name} kind #{i} name"
        assert_equal ok["effect"], k.effect, "#{ch.name} kind #{i} effect"
        assert_equal ok["variable"], k.variable, "#{ch.name} kind #{i} variable"
      end
      assert_equal v["states"], ch.states, "#{ch.name}: states"
      assert_equal v["transitions"].length, ch.transitions.length, "#{ch.name}: transition count"
      v["transitions"].each_with_index do |ot, i|
        assert_equal [ot["from"], ot["to"]], ch.transitions[i], "#{ch.name} transition #{i}"
      end
      assert_equal v["errors"], ch.errors, "#{ch.name}: errors"
    end
  end

  # ---- TestCompleteness: all twenty channels present 0..19, none thinned. --------------------

  def test_completeness
    seen = {}
    C.each do |ch|
      refute_empty ch.kinds, "#{ch.name} has no kinds (thinned surface)"
      ch.kinds.each do |k|
        assert k.effect <= Naalp::Channels::DE, "#{ch.name}.#{k.name} has invalid effect #{k.effect}"
      end
      seen[ch.id] = true
    end
    (0..0x0013).each { |id| assert seen[id], "channel #{'0x%04x' % id} missing" }
  end

  # ---- Channel(id): the ChannelSpec lookup surface (mirrors Go channels.Channel / Rust
  # channels::channel). -------------------------------------------------------------------------

  def test_channel_lookup_by_id
    c = Naalp::Channels.channel(0x0011)
    refute_nil c, "Workflow channel must be registered"
    assert_equal 0x0011, c.id
    assert_equal "Workflow", c.name
    assert_equal C[17].kinds.length, c.kinds.length
    assert_nil Naalp::Channels.channel(0x00FF), "unregistered channel id must be nil"
  end

  # ---- TestStateMachine: representative channels permit their declared transitions and reject
  # others -- mirrors channels_test.go's TestStateMachine table byte-for-byte. -------------------

  def test_state_machine
    cases = [
      [0x0001, "offered", "accepted", true],    # Memory
      [0x0001, "live", "revoked", true],         # Memory
      [0x0001, "revoked", "live", false],        # Memory regression
      [0x000E, "order", "fulfil", true],         # Commerce
      [0x000E, "offer", "fulfil", false],        # Commerce skip
      [0x0011, "awaiting-input", "running", true],  # Workflow
      [0x0011, "created", "running", false],        # Workflow gate skip
    ]
    cases.each do |ch, from, to, ok|
      got = Naalp::Channels.allowed_transition(ch, from, to)
      assert_equal ok, got, "channel #{'0x%04x' % ch} #{from}->#{to} allowed=#{got} want #{ok}"
    end
    # An unregistered channel id permits nothing.
    refute Naalp::Channels.allowed_transition(0x00FF, "a", "b")
  end

  # ---- TestTransformCycle: Spatial's named error fires on a cyclic coordinate-frame tree, and a
  # valid (acyclic) tree is accepted -- mirrors channels_test.go's TestTransformCycle exactly (same
  # tree shapes). ---------------------------------------------------------------------------------

  def test_transform_cycle
    tree = { "base" => "", "arm" => "base", "hand" => "arm" }
    assert_nil Naalp::Channels.check_frame_tree(tree)

    cyclic = { "a" => "b", "b" => "c", "c" => "a" }
    err = assert_raises(Naalp::Channels::TransformCycle) { Naalp::Channels.check_frame_tree(cyclic) }
    assert_equal "TransformCycle", err.kind
  end

  # A frame whose parent key has no entry of its own is a root, same as an explicit "".
  def test_transform_cycle_absent_parent_is_root
    tree = { "child" => "unlisted" }
    assert_nil Naalp::Channels.check_frame_tree(tree)
  end

  # A direct self-loop (a frame naming itself as its own parent) is a 1-node cycle.
  def test_transform_cycle_self_loop
    err = assert_raises(Naalp::Channels::TransformCycle) { Naalp::Channels.check_frame_tree({ "x" => "x" }) }
    assert_equal "TransformCycle", err.kind
  end

  # ==== Workflow input gate (design-channels.md §18): the crash test that InputGateBypass cannot
  # occur -- mirrors channels_test.go's TestWorkflowInputGateBypass / channels.rs's
  # workflow_input_gate_bypass byte-for-byte (same script). FAIL-CLOSED anchor / mutation target. ==

  def test_workflow_input_gate_bypass
    Dir.mktmpdir do |d|
      path = File.join(d, "wf")
      g = Naalp::Channels.open_workflow_gate(path)
      begin
        g.create("t1", false)

        # Running before input is InputGateBypass.
        err = assert_raises(Naalp::Channels::InputGateBypass) { g.run("t1") }
        assert_equal "InputGateBypass", err.kind
      ensure
        # Always closed, even if an assertion above fails, so a failing run never leaks an open
        # WAL handle (Windows refuses to remove a directory containing an open file).
        g.close
      end

      # Simulate a crash right after Create: close, then reopen -- the durable status is still the
      # pre-gate status (persist-before-ack means a crash can never manufacture a bypass).
      g2 = Naalp::Channels.open_workflow_gate(path)
      begin
        assert_equal "awaiting-input", g2.status("t1"), "crash bypassed the gate"

        err = assert_raises(Naalp::Channels::InputGateBypass) { g2.run("t1") }
        assert_equal "InputGateBypass", err.kind

        # Supplying input opens the gate; only then may it run.
        g2.supply_input("t1")
        g2.run("t1")
        assert_equal "running", g2.status("t1")
      ensure
        g2.close
      end
    end
  end

  # A task requiring approval gates on SupplyInput (approval), not TaskInput; Run before approval
  # is InputGateBypass exactly as the input-gated path.
  def test_workflow_approval_gate_bypass
    Dir.mktmpdir do |d|
      g = Naalp::Channels.open_workflow_gate(File.join(d, "wf2"))
      begin
        g.create("t2", true)
        assert_equal "awaiting-approval", g.status("t2")
        err = assert_raises(Naalp::Channels::InputGateBypass) { g.run("t2") }
        assert_equal "InputGateBypass", err.kind
        g.supply_input("t2")
        assert_equal "approved", g.status("t2")
        g.run("t2")
        assert_equal "running", g.status("t2")
      ensure
        g.close
      end
    end
  end

  # Re-creating an already-known task, or running/supplying an unknown task, is TaskStateError --
  # never a silent success and never InputGateBypass (a different named error for a different
  # protocol violation).
  def test_workflow_task_state_error
    Dir.mktmpdir do |d|
      g = Naalp::Channels.open_workflow_gate(File.join(d, "wf3"))
      begin
        g.create("t1", false)
        err = assert_raises(Naalp::Channels::TaskStateError) { g.create("t1", false) }
        assert_equal "TaskStateError", err.kind

        err = assert_raises(Naalp::Channels::TaskStateError) { g.run("unknown") }
        assert_equal "TaskStateError", err.kind

        err = assert_raises(Naalp::Channels::TaskStateError) { g.supply_input("unknown") }
        assert_equal "TaskStateError", err.kind
      ensure
        g.close
      end
    end
  end
end
