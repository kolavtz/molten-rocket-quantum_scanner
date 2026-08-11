import traceback
try:
    from apply_models_schema import apply
    apply()
except Exception as e:
    with open("error.log", "w") as f:
        f.write(traceback.format_exc())
