from aegisledger.api import ExperimentRequest
from aegisledger.evaluation import create_experiment_spec
from aegisledger.experiment_store import (
    ExperimentJob,
    ExperimentResponseV1,
    MemoryExperimentStore,
)


def job(status="QUEUED"):
    request = ExperimentRequest(
        seed="durable-job",
        scenarios=("II-tool-poisoning",),
        runs_per_scenario=1,
    )
    spec = create_experiment_spec(
        seed=request.seed,
        scenarios=request.scenarios,
        runs_per_scenario=request.runs_per_scenario,
        commit_sha="0" * 40,
    )
    return ExperimentJob(
        response=ExperimentResponseV1(
            experiment_id=spec.experiment_id,
            status=status,
            seed=spec.seed,
            configuration_hash=spec.configuration_hash,
        ),
        request=request.model_dump(mode="json"),
        principal_id="researcher",
    )


def test_job_is_claimed_once_and_terminal_result_is_retained():
    store = MemoryExperimentStore()
    queued = store.create(job())

    running = store.claim(queued.response.experiment_id)

    assert running is not None
    assert running.response.status == "RUNNING"
    assert store.claim(queued.response.experiment_id) is None
    finished = store.finish(
        running.response.model_copy(
            update={"status": "COMPLETED", "summary": {"raw_run_count": 5}}
        )
    )
    assert finished.response.status == "COMPLETED"
    assert finished.response.summary == {"raw_run_count": 5}
    assert store.active_count("researcher") == 0


def test_restart_requeues_interrupted_running_job():
    store = MemoryExperimentStore()
    queued = store.create(job())
    assert store.claim(queued.response.experiment_id) is not None

    assert store.requeue_running() == 1

    recovered = store.get(queued.response.experiment_id)
    assert recovered is not None
    assert recovered.response.status == "QUEUED"
    assert store.claim(queued.response.experiment_id) is not None
