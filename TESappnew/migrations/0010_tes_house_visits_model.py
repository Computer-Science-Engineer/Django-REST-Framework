# Generated by Django 4.1.5 on 2023-03-06 06:24

from django.db import migrations, models
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('TESappnew', '0009_rename__id_tes_submit_new_house_model_id_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='TES_house_visits_model',
            fields=[
                ('id', djongo.models.fields.ObjectIdField(auto_created=True, db_column='_id', primary_key=True, serialize=False)),
                ('house_id', models.CharField(max_length=100)),
                ('report_template', models.CharField(max_length=100)),
                ('report_status', models.CharField(max_length=100)),
            ],
            options={
                'verbose_name_plural': 'house_visits',
                'db_table': 'house_visits',
            },
        ),
    ]
