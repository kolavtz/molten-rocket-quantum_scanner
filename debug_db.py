import sys, traceback
sys.path.insert(0, ".")
try:
    from apply_models_schema import apply
    apply()
except Exception as e:
    print("DB ERROR DETECTED:")
    print(repr(e))
    import sqlalchemy.exc
    if isinstance(e, sqlalchemy.exc.OperationalError):
        print(e.orig)
